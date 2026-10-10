# Apollo

Errata mirroring and publishing system

# Features

* Red Hat advisory indexing
* Mirroring Red Hat advisories onto rebuild products
* Output updateinfo for RPM repositories

# Planned features

* Custom advisories
* Vulnerability/errata lifecycle tracker

# Requirements

* PostgreSQL
* Temporal
* Bazel

# Development Guide
Setting up a development environment for Apollo involves setting up a local PostgreSQL database, Temporal server, Apollo server, and associated workers. Once you have these running, you can test changes made to the Apollo code.

## Prerequisites
1. Podman or Docker
1. PostgreSQL client (`psql`)
1. Temporal CLI: [link](https://docs.temporal.io/cli)
1. Local checkout of distro-tools
1. Bazel CLI (bazelisk): [link](https://github.com/bazelbuild/bazelisk/blob/master/README.md)

## Steps:
These steps assume you are currently in the root of the cloned distro-tools repository.
1. Create a directory for PostgreSQL DB: `mkdir -p container_data/postgres`
1. Spin up PostgreSQL container:
   - **Podman:** `podman run -d -v $PWD/container_data/postgres:/var/lib/postgresql/data:z,rw -e POSTGRES_PASSWORD=postgres -p 5432:5432 --security-opt=label=disable --name postgres_apollo docker.io/postgres:14`
   - **Docker:** `docker run -d -v $PWD/container_data/postgres:/var/lib/postgresql/data:z,rw -e POSTGRES_PASSWORD=postgres -p 5432:5432 --name postgres_apollo docker.io/postgres:14`
1. Connect to PostgreSQL: `PGPASSWORD=postgres psql -U postgres -h 127.0.0.1`
1. Once at the PostgreSQL prompt, create the database: `create database apollo2development template template0; grant all on database apollo2development to postgres;`
1. Exit PostgreSQL: `quit;`
1. Create needed tables: `PGPASSWORD=postgres psql -U postgres -h 127.0.0.1 apollo2development -f apollo/schema.sql`
1. Seed the needed values in the DB: `PGPASSWORD=postgres psql -U postgres -h 127.0.0.1 apollo2development -c "\copy codes from 'apollo/db_seed/codes.csv' with DELIMITER ',';" -c "\copy supported_products from 'apollo/db_seed/supported_products.csv' with DELIMITER ',';" -c "\copy supported_products_rh_mirrors from 'apollo/db_seed/supported_products_rh_mirrors.csv' with DELIMITER ',';" -c "\copy supported_products_rpm_repomds from 'apollo/db_seed/supported_products_rpm_repomds.csv' with DELIMITER ',';"`
1. Start the Temporal server (can be run in a tmux or screen session): `temporal server start-dev`
1. Start the Apollo server (can be run in a tmux or screen session): `bazel run apollo/server:server`
1. Start the rhworker (can be run in a tmux or screen session): `bazel run apollo/rhworker:rhworker`
1. Start the rpmworker (can be run in a tmux or screen session): `bazel run apollo/rpmworker:rpmworker`

Setup is now complete.

To start a job to ingest Red Hat advisories: `temporal workflow start --type PollRHAdvisoriesWorkflow --task-queue v2-rhworker`

To start a job to clone Red Hat security advisories over to Rocky: `temporal workflow start --type RhMatcherWorkflow --task-queue v2-rpmworker`

## Tips and Tricks
* You can reduce the number of advisories pulled down from Red Hat on first sync by setting the `last_indexed_at` date: `PGPASSWORD=postgres psql -U postgres -h 127.0.0.1 apollo2development -c "update red_hat_index_state set last_indexed_at = '2024-11-01';"` — run this after seeding but before starting the workers. Adjust the date to whatever works for you.
* You can redirect the logging for a worker to a file using something like: `bazel run apollo/rpmworker:rpmworker &> rpmworker.log`
* The Apollo web UI is available on port `9999`
* The Temporal web UI is available on port `8233`

## Recovering historical advisory package associations

The live repository matcher cannot recover a fixed build after that build has
aged out of repodata. Existing advisories created by an older matcher can also
retain incorrect package associations after the matching code is fixed. For
example, numeric prefix matching previously allowed `krb5-1.21.1-10` to stand
in for `krb5-1.21.1-1` (rocky-linux/peridot#204). The current matcher rejects
that alias, but that alone does not repair already-published records.
Deploy the corrected matcher (including PR #98) before recovering those records.

`apollo.rpmworker.repair_advisory` reconstructs one existing advisory from
explicit historical repositories, using the source RH advisory stored in the
database and the existing matcher. It does not substitute Red Hat checksums
or RPM NEVRAs for actual Rocky packages.

Create a JSON manifest of historical repositories for **every mirror already
represented in the advisory's packages**. Multiple repositories per mirror
are allowed (e.g. BaseOS, AppStream, and devel). Mirror IDs refer to existing
`supported_products_rh_mirrors` rows; the command does not alter their URLs.

```json
[
  {
    "mirror_id": 123,
    "repo_name": "BaseOS",
    "url": "https://dl.rockylinux.org/vault/rocky/9.3/BaseOS/x86_64/os/repodata/repomd.xml",
    "debug_url": "https://dl.rockylinux.org/vault/rocky/9.3/BaseOS/x86_64/debug/tree/repodata/repomd.xml",
    "source_url": "http://127.0.0.1:8765/source/repodata/repomd.xml"
  }
]
```

Some vault source trees contain SRPMs but no repodata. In that case, download
the source advisory's historical Rocky SRPMs, verify their signatures, and
create a local source repository with `createrepo_c`. Serve its repodata over
HTTP, for example on loopback, and use that address as `source_url`. Missing
debug packages or architectures require additional historical repositories;
the command rejects incomplete replacements rather than removing binaries.
The example manifest is a format illustration, not a complete manifest for
the multi-architecture production RLSA-2023:6699 record.

Use the same `ENV`, `DB_HOST`, `DB_PORT`, `DB_USER`, and `DB_PASSWORD`
configuration as the RPM worker. PostgreSQL and the database schema are
required; a running Temporal server is not needed for this command.

```bash
# Preview: matcher writes are rolled back, including workflow-state changes.
python3 -m apollo.rpmworker.repair_advisory \
  --advisory RLSA-2023:6699 --archives archives.json

# Apply the package replacement atomically.
python3 -m apollo.rpmworker.repair_advisory \
  --advisory RLSA-2023:6699 --archives archives.json --apply
```

The command checks epoch, major version, architecture, source-advisory matching
and existing binary coverage. It replaces only the advisory's packages and
updates its modification timestamp. Its publication date, CVEs, fixes, topic,
mirror configuration, blocks and overrides are preserved. Concurrent package
changes abort the replacement; repeating a completed repair is a no-op.

After applying a repair, run the normal updateinfo publishing and OSV export
jobs to refresh downstream artifacts. This command does not publish feeds.

### Regression tests

```bash
python3 -m pytest apollo/tests/test_repair_advisory.py \
  apollo/tests/test_rh_matcher_activities.py apollo/tests/test_api_osv.py

bazel test //apollo/tests:test_repair_advisory
```

Recovery tests use in-memory SQLite by default. To additionally test locking
and nested transactions on PostgreSQL, set `APOLLO_REPAIR_TEST_DB` to a
dedicated test database URL. These tests create their own fixtures and clean
up only those fixtures.
