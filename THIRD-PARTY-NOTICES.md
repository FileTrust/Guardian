# Third-party software and credits

FileTrust's own code is covered by `LICENSE` (FSL-1.1-ALv2). Third-party software
retains its own license and copyright notices; FileTrust's license does not
replace those terms.

## Container platform and base image

The Dockerfile uses the digest-pinned Docker Official Image
[`python:3.12-slim-bookworm`](https://hub.docker.com/_/python).
Python and Debian packages retain their upstream license and copyright files
inside the image, including Debian's `/usr/share/doc` notices. FileTrust's
license does not replace those notices. Docker Engine and Compose are installed
separately on the host; their sources are maintained at
https://github.com/moby/moby and https://github.com/docker/compose.

## ZoKrates 0.8.8 — LGPL-3.0

ZoKrates contributors provide the proof-generation toolbox used by this node.
Thank you to the ZoKrates project and contributors.

* Project: https://github.com/Zokrates/ZoKrates
* Exact source: https://github.com/Zokrates/ZoKrates/tree/0.8.8
* Upstream license: https://github.com/Zokrates/ZoKrates/blob/0.8.8/LICENSE
* Release: https://github.com/Zokrates/ZoKrates/releases/tag/0.8.8
* Local texts: `licenses/ZoKrates-LICENSE`, `licenses/LGPL-3.txt`,
  `licenses/GPL-3.txt`.

`runtime/core/g_poseidon.py` is a fixed-width Python adaptation of ZoKrates
0.8.8's `hashes/poseidon/poseidon.zok` and public round constants. That adapter
retains LGPL-3.0-only and its upstream attribution; the application license
does not replace it. Its complete adapted source is distributed in this
repository. Original source is in the tagged `zokrates_stdlib/stdlib/` tree
linked above. The adaptation is limited to two inputs over the BN254 field.

The installer downloads the original standalone executable directly from that
official upstream release. FileTrust does not include a ZoKrates executable in
this repository or its installer ZIP. The signed manifest pins both archive
and executable SHA-256, size, version and extraction member. The executable is
invoked as a separate process. The stdlib, compiler source and upstream tests
are not extracted into the node installation; compiled circuits need only the
executable at runtime. The original executable may be replaced under upstream's
terms; startup integrity checks must then be updated through an approved
artifact release rather than silently accepting unverified code.

Copying a ZoKrates binary into a future FileTrust release would be a different
distribution: applicable LGPL/GPL notice and corresponding-source conditions
must be handled before doing that. Credits alone are not a substitute.

## Python dependencies — installed from PyPI

The installer fetches these pinned dependencies through pip. Their package
licenses/notices remain with them in the virtual environment. The production
repository and installer ZIP do not vendor Python dependency code or wheels.

* **web3.py 7.16.0**, Ethereum Foundation and contributors — MIT.
  https://github.com/ethereum/web3.py
  Local upstream text: `licenses/web3-LICENSE`.
* **eth-account 0.13.7**, Ethereum Foundation and contributors — MIT.
  https://github.com/ethereum/eth-account
  Local upstream text: `licenses/eth-account-LICENSE`.
* **cryptography 49.0.0**, Python Cryptographic Authority and contributors —
  Apache-2.0 OR BSD-3-Clause, as stated in its upstream license.
  https://github.com/pyca/cryptography
  Local texts: `licenses/cryptography-LICENSE`,
  `licenses/cryptography-LICENSE.APACHE`, `licenses/cryptography-LICENSE.BSD`.
* **Requests 2.34.2**, Kenneth Reitz and contributors — Apache-2.0.
  https://github.com/psf/requests
  Local texts: `licenses/requests-LICENSE`, `licenses/requests-NOTICE`.

pip also installs these packages' dependencies. Their own wheel metadata and
license texts remain installed. This list is not a claim that transitive
dependencies all have the same license; for example certifi uses MPL-2.0.
If a future frozen application bundles those libraries, review the actual
bundled dependency set and redistribution requirements at that time.

## Cryptographic specifications

The zkDKG encrypted-share accountability circuit model derives from
**soberm/zkDKG**, under MIT: https://github.com/soberm/zkDKG . Its original
copyright and complete license are retained in `licenses/zkDKG-MIT.txt`.
The circuits also use ZoKrates standard-library gadgets, credited above.
Compiled circuit/source provenance and any applicable source-distribution
conditions need to be retained when promoting artifact releases publicly;
the fact that an output is produced by a compiler alone does not settle its
license. This private test release does not certify that separate source audit.

The implementation uses secp256k1 parameters from SECG SEC 2, and Baby Jubjub
parameters described by EIP-2494 (Barry WhiteHat, Marta Bellés and Jordi Baylina):
https://eips.ethereum.org/EIPS/eip-2494 . These credits identify specifications;
they do not assert authorship of FileTrust's runtime by those contributors.

The public proving artifacts are deployed circuit/setup parameters. They are
not copies of the ZoKrates executable, wallet keys or private DKG shares.
They are not Solidity verifier source files. If Solidity source is ever
distributed with the app, preserve the notices of its actual upstream template
and libraries in addition to these notices.

## Application update checks

The Update Framework (`tuf` 7.0.1), Copyright the TUF contributors, is
available under Apache-2.0 OR MIT. FileTrust uses the MIT option.
https://github.com/theupdateframework/python-tuf

`securesystemslib`, Copyright the Secure Systems Lab contributors, is MIT.
https://github.com/secure-systems-lab/securesystemslib

Full license texts are in `licenses/tuf-MIT.txt`,
`licenses/tuf-APACHE-2.0.txt` and `licenses/securesystemslib-MIT.txt`.
These dependencies are installed separately through pip; their own notices
and dependency licenses remain in the installed distributions.
