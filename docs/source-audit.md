# Source audit

The initial architecture was informed by public behavior and project structure from these tools. No source code was copied into this repository.

| Project | Revision inspected | Useful design observation | License |
|---|---|---|---|
| zsteg | `b75b578ea13ed207561a46b8620b843c0a894422` | Separate extraction parameters, scan checks and result analysis | MIT declaration in README |
| StegoVeritas | `4d4929be54f0c40a30f02a31a0ad24356a4fdc41` | Staged metadata, transform, LSB, frame and trailing-data workflow | GPL-2.0 |
| ST3GG | `35f8b2b8529a74091c97ce622ee0cbf1ae3bd260` | Named analysis registry and subprocess-friendly JSON interface | AGPL-3.0 |

Implementation work should use published file-format specifications and independently authored tests. Reference projects may supply behavioral comparison cases and public samples, with provenance recorded alongside each corpus item.
