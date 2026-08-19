# Honey 0.9.3 PyPI release gate

The bounded Python publication target is `hol-cigar==0.9.3`, imported as `cigar_sdk`. Publication is
an alpha developer preview and requires the exact `v0.9.3` tag, owner approval, protected `pypi`
environment, Trusted Publishing, attestations, strict metadata checks, clean Python 3.14 installs,
and byte-for-byte agreement with the Honey release manifest.

The workflow must fail closed if the wheel or sdist differs from
`hol_cigar-0.9.3-py3-none-any.whl` or `hol_cigar-0.9.3.tar.gz`, if any mandatory Python publication
gate lacks evidence, or if the candidate has already been published. Python package qualification
does not imply full Honey runtime, efficiency, efficacy, platform, signing, or production
qualification.
