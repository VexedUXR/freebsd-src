import os
import json

def match(kern_all, world_all, kern_changes, world_changes):
  all = ["amd64", "armv7", "aarch64", "i386", "powerpc", "powerpc64", "powerpc64le", "riscv64"]
  out = open(os.environ['GITHUB_OUTPUT'], "a")

  kern_archs = []
  kern_excl = set()
  make_targets = []
  if kern_changes != []:
    make_targets.append("buildkernel")

    if kern_all == "true":
      kern_archs = all
    else:
      kern_archs = kern_changes

    kern_excl = set(all) ^ set(kern_archs)

  world_archs = []
  world_excl = set()
  if world_changes != []:
    make_targets.append("buildworld")

    if world_all == "true":
      world_archs = all             
    else:
      world_archs = world_changes

    world_excl = set(all) ^ set(world_archs)

  print("kern_archs: ", kern_archs)
  print("world_archs: ", world_archs)

  archs = set(world_archs + kern_archs)

  # No need to exclude architectures we're not building.
  kern_excl &= archs
  world_excl &= archs

  target_dict = {
    "amd64":    "amd64",
    "armv7":    "arm",
    "i386":     "i386",
    "aarch64":  "arm64",
    "riscv64":  "riscv",
    "powerpc":  "powerpc",
    "powerpc64":"powerpc",
    "powerpc64le":"powerpc",
  }

  archs_map = []
  for a in archs:
    archs_map.append({ "target": target_dict[a], "target_arch": a })

  exclude = []
  for a in kern_excl:
    exclude += [{ "make_target": "buildkernel" }, { "arch": a }]
  for a in world_excl:
    exclude += [{ "make_target": "buildworld" }, { "arch": { "target": target_dict[a], "target_arch": a } }]

  print("exclude=" + json.dumps(exclude) + '\n')
  print("make_targets=" + json.dumps(make_targets) + '\n')
  print("archs=" + json.dumps(archs_map) + '\n')

  out.write("exclude=" + json.dumps(exclude) + '\n')
  out.write("make_targets=" + json.dumps(make_targets) + '\n')
  out.write("archs=" + json.dumps(archs_map) + '\n')
  out.close()
