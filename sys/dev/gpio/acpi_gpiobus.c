/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Ahmad Khalifa <ahmadkhalifa570@gmail.com>
 * Copyright (c) 2024 Colin Percival
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/gpio.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>

#include <dev/gpio/gpiobusvar.h>

struct acpi_gpiobus_aei_info {
	struct resource *irq_res;
	ACPI_HANDLE handle;
	void *cookie;
	int rid;
	enum {
		ACPI_AEI_TYPE_UNKNOWN,
		ACPI_AEI_TYPE_ELX,
		ACPI_AEI_TYPE_EVT
	} type;
};

struct acpi_gpiobus_softc {
	struct gpiobus_softc	super_sc;
	struct acpi_gpiobus_aei_info	*sc_aei_info;
	ACPI_CONNECTION_INFO	handler_info;
};

struct acpi_gpiobus_ctx {
	struct acpi_gpiobus_softc	*sc;
	ACPI_HANDLE		dev_handle;
};

static uint32_t
acpi_gpiobus_convflags(ACPI_RESOURCE_GPIO *gpio_res)
{
	uint32_t flags = 0;

	/* Figure out pin flags */
	if (gpio_res->ConnectionType == ACPI_RESOURCE_GPIO_TYPE_INT) {
		switch (gpio_res->Polarity) {
		case ACPI_ACTIVE_HIGH:
			flags = gpio_res->Triggering == ACPI_LEVEL_SENSITIVE ?
			    GPIO_INTR_LEVEL_HIGH : GPIO_INTR_EDGE_RISING;
			break;
		case ACPI_ACTIVE_LOW:
			flags = gpio_res->Triggering == ACPI_LEVEL_SENSITIVE ?
			    GPIO_INTR_LEVEL_LOW : GPIO_INTR_EDGE_FALLING;
			break;
		case ACPI_ACTIVE_BOTH:
			flags = GPIO_INTR_EDGE_BOTH;
			break;
		}

		flags |= GPIO_PIN_INPUT;
#ifdef NOT_YET
		/* This is not currently implemented. */
		if (gpio_res->Shareable == ACPI_SHARED)
			flags |= GPIO_INTR_SHAREABLE;
#endif
	}
	if (gpio_res->ConnectionType == ACPI_RESOURCE_GPIO_TYPE_IO) {
		switch (gpio_res->IoRestriction) {
		case ACPI_IO_RESTRICT_INPUT:
			flags |= GPIO_PIN_INPUT;
			break;
		case ACPI_IO_RESTRICT_OUTPUT:
			flags |= GPIO_PIN_OUTPUT;
			break;
		}
	}

	switch (gpio_res->PinConfig) {
	case ACPI_PIN_CONFIG_PULLUP:
		flags |= GPIO_PIN_PULLUP;
		break;
	case ACPI_PIN_CONFIG_PULLDOWN:
		flags |= GPIO_PIN_PULLDOWN;
		break;
	}

	return (flags);
}

static void
acpi_gpiobus_aei_intr(void *arg)
{
	struct acpi_gpiobus_aei_info *aei_info = arg;

	/* Ask ACPI to run the appropriate _EVT, _Exx or _Lxx method. */
	if (aei_info->type == ACPI_AEI_TYPE_EVT)
		acpi_SetInteger(aei_info->handle, NULL, aei_info->rid);
	else
		AcpiEvaluateObject(aei_info->handle, NULL, NULL, NULL);
}

static ACPI_STATUS
acpi_gpiobus_enumerate_res(ACPI_RESOURCE *res, void *context)
{
	ACPI_RESOURCE_GPIO *gpio_res = &res->Data.Gpio;
	struct acpi_gpiobus_ctx *ctx = context;
	struct gpiobus_softc *super_sc = &ctx->sc->super_sc;
	ACPI_HANDLE handle;
	uint32_t flags, i;

	if (res->Type != ACPI_RESOURCE_TYPE_GPIO)
		return (AE_OK);

	if (ACPI_FAILURE(AcpiGetHandle(ACPI_ROOT_OBJECT,
	    gpio_res->ResourceSource.StringPtr, &handle)) ||
	    handle != ctx->dev_handle)
		return (AE_OK);

	if (__predict_false(gpio_res->PinTableLength > super_sc->sc_npins)) {
		device_printf(super_sc->sc_busdev,
		    "invalid pin table length %hu, max: %d (bad ACPI tables?)\n",
		    gpio_res->PinTableLength, super_sc->sc_npins);
		return (AE_LIMIT);
	}

	flags = acpi_gpiobus_convflags(gpio_res);
	for (i = 0; i < gpio_res->PinTableLength; i++) {
		UINT16 pin = gpio_res->PinTable[i];

		if (__predict_false(pin >= super_sc->sc_npins)) {
			device_printf(super_sc->sc_busdev,
			    "invalid pin 0x%x, max: 0x%x (bad ACPI tables?)\n",
			    pin, super_sc->sc_npins - 1);
			return (AE_LIMIT);
		}

		GPIO_PIN_SETFLAGS(super_sc->sc_dev, pin, flags &
		    ~GPIO_INTR_MASK);
	}

	return (AE_OK);
}

static ACPI_STATUS
acpi_gpiobus_enumerate_aei(ACPI_RESOURCE *res, void *context)
{
	ACPI_RESOURCE_GPIO *gpio_res = &res->Data.Gpio;
	struct acpi_gpiobus_ctx *ctx = context;
	struct acpi_gpiobus_softc *sc = ctx->sc;
	device_t dev = sc->super_sc.sc_busdev;

	/*
	 * Check that we have a GpioInt object.
	 * Note that according to the spec this
	 * should always be the case.
	 */
	if (res->Type != ACPI_RESOURCE_TYPE_GPIO)
		return (AE_OK);
	if (gpio_res->ConnectionType != ACPI_RESOURCE_GPIO_TYPE_INT)
		return (AE_OK);

	for (int i = 0; i < gpio_res->PinTableLength; i++) {
		struct resource *res;
		uint32_t flags, irq, pin = gpio_res->PinTable[i];
		int err;
#ifdef INTRNG
		struct intr_map_data_gpio *gpio_data;
#endif

		flags = acpi_gpiobus_convflags(gpio_res);
		if (pin <= 255) {
			char objname[5];	/* "_EXX" or "_LXX" */
			sprintf(objname, "_%c%02X",
			    (flags & GPIO_INTR_EDGE_MASK) ? 'E' : 'L', pin);
			if (ACPI_SUCCESS(AcpiGetHandle(ctx->dev_handle, objname,
			    &sc->sc_aei_info[pin].handle)))
				sc->sc_aei_info[pin].type = ACPI_AEI_TYPE_ELX;
		}

		if (sc->sc_aei_info[pin].type == ACPI_AEI_TYPE_UNKNOWN) {
			if (ACPI_SUCCESS(AcpiGetHandle(ctx->dev_handle, "_EVT",
			    &sc->sc_aei_info[pin].handle)))
				sc->sc_aei_info[pin].type = ACPI_AEI_TYPE_EVT;
			else {
				device_printf(dev,
				    "AEI Device type is unknown for pin 0x%x\n",
				    pin);
				continue;
			}
		}

		err = gpiobus_acquire_pin(dev, pin);
		if (err != 0) {
			device_printf(dev, "Failed to acquire pin 0x%x\n", pin);
			continue;
		}

		err = GPIO_PIN_SETFLAGS(sc->super_sc.sc_dev, pin,
		    flags & ~GPIO_INTR_MASK);
		if (err != 0) {
			device_printf(dev,
			    "Failed to set pin flags for pin 0x%x\n", pin);
			gpiobus_release_pin(dev, pin);
			continue;
		}

#ifdef INTRNG
		gpio_data = (struct intr_map_data_gpio *)intr_alloc_map_data(
		    INTR_MAP_DATA_GPIO, sizeof(*gpio_data), M_WAITOK | M_ZERO);
		gpio_data->gpio_pin_num = pin;
		gpio_data->gpio_pin_flags = 0;
		gpio_data->gpio_intr_mode = flags & GPIO_INTR_MASK;

		irq = intr_map_irq(dev, 0, (struct intr_map_data *)gpio_data);
#else
		err = gpiopic_check_intr_pin(sc->super_sc.sc_pic, pin);
		if (err != 0) {
			device_printf(dev, "PIC not set up on pin 0x%x\n", pin);
			gpiobus_release_pin(dev, pin);
			continue;
		}

		irq = pin;
#endif
		res = rman_reserve_resource(&sc->super_sc.sc_intr_rman, irq,
		    irq, 1, 0, dev);

		if (res != NULL) {
			rman_set_type(res, SYS_RES_IRQ);
#ifdef INTRNG
			/* XXX rman_set_virual? */
			err = intr_activate_irq(dev, res);
			if (err != 0) {
				rman_release_resource(res);
				res = NULL;
			}
#else
			/* XXX What about aei_info->rid? */
			rman_set_rid(res, pin);
#endif
		}

		if (res == NULL) {
			device_printf(dev,
			    "Cannot allocate an IRQ for pin 0x%x\n", pin);
#ifdef INTRNG
			intr_free_intr_map_data(
			    (struct intr_map_data *)gpio_data);
#endif
			gpiobus_release_pin(dev, pin);
			continue;
		}

#ifndef INTRNG
		gpiopic_config_intr(sc->super_sc.sc_pic, pin,
		    flags & GPIO_INTR_MASK);
#endif

		rman_activate_resource(res);
		err = BUS_SETUP_INTR(dev, dev, res, INTR_TYPE_MISC |
		    INTR_MPSAFE | INTR_EXCL | INTR_SLEEPABLE, NULL,
		    acpi_gpiobus_aei_intr, &sc->sc_aei_info[pin],
		    &sc->sc_aei_info[pin].cookie);
		if (err != 0) {
			device_printf(dev, "Cannot set up IRQ for pin 0x%x\n",
			    pin);
			rman_release_resource(res);
			gpiobus_release_pin(dev, pin);
			continue;
		}

		KASSERT(sc->sc_aei_info[pin].irq_res == NULL,
		    ("%s: duplicate pin: 0x%x",
		     device_get_nameunit(sc->super_sc.sc_dev), pin));
		sc->sc_aei_info[pin].irq_res = res;
	}

	return (AE_OK);
}

static ACPI_STATUS
acpi_gpiobus_enumerate(ACPI_HANDLE handle, UINT32 depth, void *context,
    void **result)
{
	UINT32 sta;

	/*
	 * If no _STA method or if it failed, then assume that
	 * the device is present.
	 */
	if (!ACPI_FAILURE(acpi_GetInteger(handle, "_STA", &sta)) &&
	    !ACPI_DEVICE_PRESENT(sta))
		return (AE_OK);

	if (!acpi_has_hid(handle))
		return (AE_OK);

	/* Look for GPIO resources */
	AcpiWalkResources(handle, "_CRS", acpi_gpiobus_enumerate_res, context);

	return (AE_OK);
}

static ACPI_STATUS
acpi_gpiobus_space_handler(UINT32 function, ACPI_PHYSICAL_ADDRESS address,
    UINT32 length, UINT64 *value, void *context, void *region_context)
{
	ACPI_CONNECTION_INFO *info = context;
	ACPI_RESOURCE_GPIO *gpio_res;
	device_t controller;
	ACPI_RESOURCE *res;
	ACPI_STATUS status;

	status = AcpiBufferToResource(info->Connection, info->Length, &res);
	if (ACPI_FAILURE(status) || res->Type != ACPI_RESOURCE_TYPE_GPIO)
		goto err;

	gpio_res = &res->Data.Gpio;
	controller = __containerof(info, struct acpi_gpiobus_softc,
	    handler_info)->super_sc.sc_dev;

	switch (function) {
	case ACPI_WRITE:
		if (__predict_false(
		    gpio_res->IoRestriction == ACPI_IO_RESTRICT_INPUT))
			goto err;

		for (int i = 0; i < length; i++)
			if (GPIO_PIN_SET(controller,
			    gpio_res->PinTable[address + i], (*value & 1 << i) ?
			    GPIO_PIN_HIGH : GPIO_PIN_LOW) != 0)
				goto err;
		break;
	case ACPI_READ:
		if (__predict_false(
		    gpio_res->IoRestriction == ACPI_IO_RESTRICT_OUTPUT))
			goto err;

		for (int i = 0; i < length; i++) {
			uint32_t v;

			if (GPIO_PIN_GET(controller,
			    gpio_res->PinTable[address + i], &v) != 0)
				goto err;
			*value |= v << i;
		}
		break;
	default:
		goto err;
	}

	ACPI_FREE(res);
	return (AE_OK);

err:
	ACPI_FREE(res);
	return (AE_BAD_PARAMETER);
}

static int
acpi_gpiobus_probe(device_t dev)
{
	device_t controller;

	if (acpi_disabled("gpiobus"))
		return (ENXIO);

	controller = device_get_parent(dev);
	if (controller == NULL)
		return (ENXIO);

	if (acpi_get_handle(controller) == NULL)
		return (ENXIO);

	device_set_desc(dev, "GPIO bus (ACPI-hinted)");
	return (BUS_PROBE_DEFAULT);
}

static int
acpi_gpiobus_attach(device_t dev)
{
	struct acpi_gpiobus_softc *sc;
	struct acpi_gpiobus_ctx ctx;
	ACPI_HANDLE handle;
	ACPI_STATUS status;
	int err;

	if ((err = gpiobus_attach(dev)) != 0)
		return (err);

	sc = device_get_softc(dev);
	handle = acpi_get_handle(sc->super_sc.sc_dev);
	if (handle == NULL) {
		gpiobus_detach(dev);
		return (ENXIO);
	}

	sc->sc_aei_info = malloc(
	    sizeof(struct acpi_gpiobus_aei_info)*sc->super_sc.sc_npins,
	    M_DEVBUF, M_WAITOK | M_ZERO);

	status = AcpiInstallAddressSpaceHandler(handle, ACPI_ADR_SPACE_GPIO,
	    acpi_gpiobus_space_handler, NULL, &sc->handler_info);

	if (ACPI_FAILURE(status)) {
		device_printf(dev,
		    "Failed to install GPIO address space handler\n");
		gpiobus_detach(dev);
		return (ENXIO);
	}

	ctx.dev_handle = handle;
	ctx.sc = sc;

	status = AcpiWalkNamespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT,
	    ACPI_UINT32_MAX, acpi_gpiobus_enumerate, NULL, &ctx, NULL);

	if (ACPI_FAILURE(status))
		device_printf(dev, "Failed to enumerate GPIO resources\n");

	/* Look for AEI children */
	status = AcpiWalkResources(handle, "_AEI", acpi_gpiobus_enumerate_aei,
	    &ctx);

	if (ACPI_FAILURE(status) && status != AE_NOT_FOUND)
		device_printf(dev, "Failed to enumerate AEI resources\n");

	return (0);
}

static int
acpi_gpiobus_detach(device_t dev)
{
	struct acpi_gpiobus_softc *sc;
	ACPI_STATUS status;

	sc = device_get_softc(dev);
	status = AcpiRemoveAddressSpaceHandler(
	    acpi_get_handle(sc->super_sc.sc_dev), ACPI_ADR_SPACE_GPIO,
	    acpi_gpiobus_space_handler
	);

	if (ACPI_FAILURE(status))
		device_printf(dev,
		    "Failed to remove GPIO address space handler\n");

	for (int i = 0; i < sc->super_sc.sc_npins; i++) {
		if (sc->sc_aei_info[i].irq_res != NULL) {
			struct resource *res = sc->sc_aei_info[i].irq_res;

			BUS_TEARDOWN_INTR(dev, dev, res,
			    sc->sc_aei_info[i].cookie);

#ifdef INTRNG
			intr_deactivate_irq(dev, res);
#endif
			rman_release_resource(res);
		}
	}
	free(sc->sc_aei_info, M_DEVBUF);

	return (gpiobus_detach(dev));
}

static device_method_t acpi_gpiobus_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		acpi_gpiobus_probe),
	DEVMETHOD(device_attach,	acpi_gpiobus_attach),
	DEVMETHOD(device_detach,	acpi_gpiobus_detach),

	DEVMETHOD_END
};

DEFINE_CLASS_1(gpiobus, acpi_gpiobus_driver, acpi_gpiobus_methods,
    sizeof(struct acpi_gpiobus_softc), gpiobus_driver);
EARLY_DRIVER_MODULE(acpi_gpiobus, gpio, acpi_gpiobus_driver, NULL, NULL,
    BUS_PASS_BUS + BUS_PASS_ORDER_MIDDLE);
MODULE_VERSION(acpi_gpiobus, 1);
MODULE_DEPEND(acpi_gpiobus, acpi, 1, 1, 1);
