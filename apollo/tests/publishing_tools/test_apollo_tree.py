import tempfile
import shutil
import pathlib
import hashlib
from os import path, environ

import pytest

from apollo.publishing_tools import apollo_tree

from common.testing import MockResponse

data = [
    "baseos__base__repomd__x86_64.xml",
    "baseos__base__repomd__aarch64.xml",
    "appstream__base__repomd__x86_64.xml",
    "appstream__base__repomd__aarch64.xml",
]


async def _setup_test_baseos(directory: str):
    file = data[0]
    base_dir = path.join(
        directory,
        "BaseOS/x86_64/os/repodata",
    )
    pathlib.Path(base_dir).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        path.join(path.dirname(__file__), "data", file),
        path.join(base_dir, "repomd.xml"),
    )

    # Run scan_path
    repos = await apollo_tree.scan_path(
        directory,
        "$reponame/$arch/os/repodata/repomd.xml",
        [],
    )

    return repos


@pytest.mark.asyncio
async def test_scan_path_valid_structure():
    with tempfile.TemporaryDirectory() as directory:
        # Copy test data to temp dir
        for file in data:
            fsplit = file.split("__")
            base_dir = path.join(
                directory,
                fsplit[0],
                fsplit[-1].removesuffix(".xml"),
                "os/repodata",
            )
            pathlib.Path(base_dir).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(
                path.join(path.dirname(__file__), "data", file),
                path.join(base_dir, "repomd.xml"),
            )

        # Run scan_path
        repos = await apollo_tree.scan_path(
            directory,
            "$reponame/$arch/os/repodata/repomd.xml",
            [],
        )

        assert "baseos" in repos
        assert "appstream" in repos
        assert len(repos["baseos"]) == 2
        assert len(repos["appstream"]) == 2

        for repo in repos["baseos"]:
            assert repo["name"] == "baseos"
            assert repo["arch"] in ["x86_64", "aarch64"]
            assert repo["found_path"] == path.join(
                directory,
                "baseos",
                repo["arch"],
                "os/repodata/repomd.xml",
            )

        for repo in repos["appstream"]:
            assert repo["name"] == "appstream"
            assert repo["arch"] in ["x86_64", "aarch64"]
            assert repo["found_path"] == path.join(
                directory,
                "appstream",
                repo["arch"],
                "os/repodata/repomd.xml",
            )


@pytest.mark.asyncio
async def test_scan_path_multiple_formats():
    with tempfile.TemporaryDirectory() as directory:
        # Copy test data to temp dir
        for file in data:
            fsplit = file.split("__")
            base_dir = path.join(
                directory,
                fsplit[0],
                fsplit[-1].removesuffix(".xml"),
                "os/repodata",
            )
            pathlib.Path(base_dir).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(
                path.join(path.dirname(__file__), "data", file),
                path.join(base_dir, "repomd.xml"),
            )

        file = data[0]
        fsplit = file.split("__")
        base_dir = path.join(
            directory,
            fsplit[0],
            "source/tree/repodata",
        )
        pathlib.Path(base_dir).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            path.join(path.dirname(__file__), "data", file),
            path.join(base_dir, "repomd.xml"),
        )

        # Run scan_path
        repos = await apollo_tree.scan_path(
            directory,
            "$reponame/$arch/os/repodata/repomd.xml",
            [],
        )

        assert "baseos" in repos
        assert "appstream" in repos
        assert len(repos["baseos"]) == 2
        assert len(repos["appstream"]) == 2

        for repo in repos["baseos"]:
            assert repo["name"] == "baseos"
            assert repo["arch"] in ["source", "x86_64", "aarch64"]
            assert repo["found_path"] == path.join(
                directory,
                "baseos",
                repo["arch"],
                "os/repodata/repomd.xml",
            )

        for repo in repos["appstream"]:
            assert repo["name"] == "appstream"
            assert repo["arch"] in ["x86_64", "aarch64"]
            assert repo["found_path"] == path.join(
                directory,
                "appstream",
                repo["arch"],
                "os/repodata/repomd.xml",
            )

        # Run scan_path for source
        repos = await apollo_tree.scan_path(
            directory,
            "$reponame/source/tree/repodata/repomd.xml",
            [],
        )

        assert "baseos" in repos
        assert len(repos["baseos"]) == 1

        for repo in repos["baseos"]:
            assert repo["name"] == "baseos"
            assert repo["arch"] == "source"
            assert repo["found_path"] == path.join(
                directory,
                "baseos",
                "source",
                "tree/repodata/repomd.xml",
            )


@pytest.mark.asyncio
async def test_scan_path_valid_structure_arch_first():
    with tempfile.TemporaryDirectory() as directory:
        # Copy test data to temp dir
        for file in data:
            fsplit = file.split("__")
            base_dir = path.join(
                directory,
                fsplit[-1].removesuffix(".xml"),
                fsplit[0],
                "os/repodata",
            )
            pathlib.Path(base_dir).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(
                path.join(path.dirname(__file__), "data", file),
                path.join(base_dir, "repomd.xml"),
            )

        # Run scan_path
        repos = await apollo_tree.scan_path(
            directory,
            "$arch/$reponame/os/repodata/repomd.xml",
            [],
        )

        assert "baseos" in repos
        assert "appstream" in repos
        assert len(repos["baseos"]) == 2
        assert len(repos["appstream"]) == 2

        for repo in repos["baseos"]:
            assert repo["name"] == "baseos"
            assert repo["arch"] in ["x86_64", "aarch64"]
            assert repo["found_path"] == path.join(
                directory,
                repo["arch"],
                "baseos",
                "os/repodata/repomd.xml",
            )

        for repo in repos["appstream"]:
            assert repo["name"] == "appstream"
            assert repo["arch"] in ["x86_64", "aarch64"]
            assert repo["found_path"] == path.join(
                directory,
                repo["arch"],
                "appstream",
                "os/repodata/repomd.xml",
            )


@pytest.mark.asyncio
async def test_fetch_updateinfo_from_apollo_live():
    # This test is only run if the environment variable
    # TEST_WITH_SIDE_EFFECTS is set to 1
    if not environ.get("TEST_WITH_SIDE_EFFECTS"):
        pytest.skip("Skipping test_fetch_updateinfo_from_apollo_live")

    with tempfile.TemporaryDirectory() as directory:
        file = data[0]
        base_dir = path.join(
            directory,
            "BaseOS/x86_64/os/repodata",
        )
        pathlib.Path(base_dir).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            path.join(path.dirname(__file__), "data", file),
            path.join(base_dir, "repomd.xml"),
        )

        # Run scan_path
        repos = await apollo_tree.scan_path(
            directory,
            "$reponame/$arch/os/repodata/repomd.xml",
            [],
        )

        assert "BaseOS" in repos
        assert len(repos["BaseOS"]) == 1

        # Run fetch_updateinfo_from_apollo
        for _, repo_variants in repos.items():
            for repo in repo_variants:
                updateinfo = await apollo_tree.fetch_updateinfo_from_apollo(
                    repo,
                    "Rocky Linux 8 x86_64",
                )

                assert updateinfo is not None


@pytest.mark.asyncio
async def test_fetch_updateinfo_from_apollo_live_no_updateinfo():
    # This test is only run if the environment variable
    # TEST_WITH_SIDE_EFFECTS is set to 1
    if not environ.get("TEST_WITH_SIDE_EFFECTS"):
        pytest.skip(
            "Skipping test_fetch_updateinfo_from_apollo_live_no_updateinfo"
        )

    with tempfile.TemporaryDirectory() as directory:
        file = data[0]
        base_dir = path.join(
            directory,
            "BaseOS/x86_64/os/repodata",
        )
        pathlib.Path(base_dir).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            path.join(path.dirname(__file__), "data", file),
            path.join(base_dir, "repomd.xml"),
        )

        # Run scan_path
        repos = await apollo_tree.scan_path(
            directory,
            "$reponame/$arch/os/repodata/repomd.xml",
            [],
        )

        assert "BaseOS" in repos
        assert len(repos["BaseOS"]) == 1

        # Run fetch_updateinfo_from_apollo
        for _, repo_variants in repos.items():
            for repo in repo_variants:
                updateinfo = await apollo_tree.fetch_updateinfo_from_apollo(
                    repo,
                    "Rocky Linux 8 x86_64 NONEXISTENT",
                )

                assert updateinfo is None


@pytest.mark.asyncio
async def test_fetch_updateinfo_from_apollo_mock(mocker):
    with tempfile.TemporaryDirectory() as directory:
        repos = await _setup_test_baseos(directory)

        # Read data/updateinfo__test__1.xml
        with open(
            path.join(
                path.dirname(__file__), "data", "updateinfo__test__1.xml"
            ),
            "r",
            encoding="utf-8",
        ) as f:
            updateinfo_xml = f.read()

        resp = MockResponse(updateinfo_xml, 200)
        mocker.patch("aiohttp.ClientSession.get", return_value=resp)

        # Run fetch_updateinfo_from_apollo
        for _, repo_variants in repos.items():
            for repo in repo_variants:
                updateinfo = await apollo_tree.fetch_updateinfo_from_apollo(
                    repo,
                    "Rocky Linux 8 x86_64",
                )

                assert updateinfo == updateinfo_xml


@pytest.mark.asyncio
async def test_gzip_updateinfo(mocker):
    with tempfile.TemporaryDirectory() as directory:
        repos = await _setup_test_baseos(directory)

        # Read data/updateinfo__test__1.xml
        with open(
            path.join(
                path.dirname(__file__), "data", "updateinfo__test__1.xml"
            ),
            "r",
            encoding="utf-8",
        ) as f:
            updateinfo_xml = f.read()

        resp = MockResponse(updateinfo_xml, 200)
        mocker.patch("aiohttp.ClientSession.get", return_value=resp)

        # Run fetch_updateinfo_from_apollo
        updateinfo = None
        for _, repo_variants in repos.items():
            for repo in repo_variants:
                updateinfo = await apollo_tree.fetch_updateinfo_from_apollo(
                    repo,
                    "Rocky Linux 8 x86_64",
                )

                assert updateinfo == updateinfo_xml
                break

        # Run gzip_updateinfo
        updateinfo_gz = await apollo_tree.gzip_updateinfo(updateinfo)
        assert updateinfo_gz is not None


@pytest.mark.asyncio
async def test_write_updateinfo_to_file(mocker):
    with tempfile.TemporaryDirectory() as directory:
        repos = await _setup_test_baseos(directory)

        # Read data/updateinfo__test__1.xml
        with open(
            path.join(
                path.dirname(__file__), "data", "updateinfo__test__1.xml"
            ),
            "r",
            encoding="utf-8",
        ) as f:
            updateinfo_xml = f.read()

        resp = MockResponse(updateinfo_xml, 200)
        mocker.patch("aiohttp.ClientSession.get", return_value=resp)

        # Run fetch_updateinfo_from_apollo
        updateinfo = None
        for _, repo_variants in repos.items():
            for repo in repo_variants:
                updateinfo = await apollo_tree.fetch_updateinfo_from_apollo(
                    repo,
                    "Rocky Linux 8 x86_64",
                )

                assert updateinfo == updateinfo_xml
                break

        # Gzip first
        gzipped = await apollo_tree.gzip_updateinfo(updateinfo)

        # Run write_updateinfo_to_file
        updateinfo_file = await apollo_tree.write_updateinfo_to_file(
            repos["BaseOS"][0]["found_path"],
            gzipped,
        )

        assert updateinfo_file is not None
        assert path.exists(updateinfo_file)
        assert path.isfile(updateinfo_file)

        with open(updateinfo_file, "rb") as f:
            updateinfo_file_contents = f.read()

        # Check sha256sum against written file
        actual_hexdigest = hashlib.sha256(updateinfo_file_contents).hexdigest()
        expected_hexdigest = gzipped["gzipped_sha256sum"]
        assert actual_hexdigest == expected_hexdigest


@pytest.mark.asyncio
async def test_update_repomd_xml(mocker):
    with tempfile.TemporaryDirectory() as directory:
        repos = await _setup_test_baseos(directory)

        # Read data/updateinfo__test__1.xml
        with open(
            path.join(
                path.dirname(__file__), "data", "updateinfo__test__1.xml"
            ),
            "r",
            encoding="utf-8",
        ) as f:
            updateinfo_xml = f.read()

        resp = MockResponse(updateinfo_xml, 200)
        mocker.patch("aiohttp.ClientSession.get", return_value=resp)

        # Run fetch_updateinfo_from_apollo
        updateinfo = None
        for _, repo_variants in repos.items():
            for repo in repo_variants:
                updateinfo = await apollo_tree.fetch_updateinfo_from_apollo(
                    repo,
                    "Rocky Linux 8 x86_64",
                )

                assert updateinfo == updateinfo_xml
                break

        # Gzip first
        gzipped = await apollo_tree.gzip_updateinfo(updateinfo)

        # Run write_updateinfo_to_file
        updateinfo_file = await apollo_tree.write_updateinfo_to_file(
            repos["BaseOS"][0]["found_path"],
            gzipped,
        )

        assert updateinfo_file is not None
        assert path.exists(updateinfo_file)
        assert path.isfile(updateinfo_file)

        # Run update_repomd_xml
        # This will replace the repomd.xml file with the new one
        mocker.patch("time.time", return_value=1674284973)
        repomd_xml_path = repos["BaseOS"][0]["found_path"]
        await apollo_tree.update_repomd_xml(
            repomd_xml_path,
            gzipped,
        )

        # Check that the repomd.xml file matches baseos__base__repomd__x86_64_with_updateinfo.xml from data
        with open(
            path.join(
                path.dirname(__file__),
                "data",
                "baseos__base__repomd__x86_64_with_updateinfo.xml",
            ),
            "r",
            encoding="utf-8",
        ) as f:
            expected_repomd_xml = f.read()

        with open(repomd_xml_path, "r", encoding="utf-8") as f:
            actual_repomd_xml = f.read()

        assert actual_repomd_xml == expected_repomd_xml


@pytest.mark.asyncio
async def test_run_apollo_tree(mocker):
    with tempfile.TemporaryDirectory() as directory:
        repos = await _setup_test_baseos(directory)

        # Read data/updateinfo__test__1.xml
        with open(
            path.join(
                path.dirname(__file__), "data", "updateinfo__test__1.xml"
            ),
            "r",
            encoding="utf-8",
        ) as f:
            updateinfo_xml = f.read()

        resp = MockResponse(updateinfo_xml, 200)
        mocker.patch("aiohttp.ClientSession.get", return_value=resp)

        mocker.patch("time.time", return_value=1674284973)
        await apollo_tree.run_apollo_tree(
            "$reponame/$arch/os/repodata/repomd.xml",
            False,
            True,
            directory,
            [],
            "Rocky Linux 8 x86_64",
        )

        for _, repo_variants in repos.items():
            for repo in repo_variants:
                # Check that the repomd.xml file matches baseos__base__repomd__x86_64_with_updateinfo.xml from data
                with open(
                    path.join(
                        path.dirname(__file__),
                        "data",
                        "baseos__base__repomd__x86_64_with_updateinfo.xml",
                    ),
                    "r",
                    encoding="utf-8",
                ) as f:
                    expected_repomd_xml = f.read()

                with open(repo["found_path"], "r", encoding="utf-8") as f:
                    actual_repomd_xml = f.read()

                assert actual_repomd_xml == expected_repomd_xml


@pytest.mark.asyncio
async def test_run_apollo_tree_arch_in_product(mocker):
    with tempfile.TemporaryDirectory() as directory:
        repos = await _setup_test_baseos(directory)

        # Read data/updateinfo__test__1.xml
        with open(
            path.join(
                path.dirname(__file__), "data", "updateinfo__test__1.xml"
            ),
            "r",
            encoding="utf-8",
        ) as f:
            updateinfo_xml = f.read()

        resp = MockResponse(updateinfo_xml, 200)
        mocker.patch("aiohttp.ClientSession.get", return_value=resp)

        mocker.patch("time.time", return_value=1674284973)
        await apollo_tree.run_apollo_tree(
            "$reponame/$arch/os/repodata/repomd.xml",
            False,
            True,
            directory,
            [],
            "Rocky Linux 8 $arch",
        )

        for _, repo_variants in repos.items():
            for repo in repo_variants:
                # Check that the repomd.xml file matches baseos__base__repomd__x86_64_with_updateinfo.xml from data
                with open(
                    path.join(
                        path.dirname(__file__),
                        "data",
                        "baseos__base__repomd__x86_64_with_updateinfo.xml",
                    ),
                    "r",
                    encoding="utf-8",
                ) as f:
                    expected_repomd_xml = f.read()

                with open(repo["found_path"], "r", encoding="utf-8") as f:
                    actual_repomd_xml = f.read()

                assert actual_repomd_xml == expected_repomd_xml
