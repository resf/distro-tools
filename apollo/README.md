# Apollo

Errata mirroring and publishing system

# Features

* Mirror advisories published by Red Hat
* Supports EUS
* Supports x86_64, aarch64, ppc64, ppc64le and s390x
* Create custom advisories
* CVE indexer and lifecycle tracker (Only Red Hat Security Data API for now)
* Publish updateinfo to RPM repositories
* Support for Peridot and Koji build systems

# Requirements
* Redis
* PostgreSQL
* Gunicorn