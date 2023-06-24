import asyncio
from __init__ import API, Architecture


async def main():
    api = API()
    res = await api.search(
        detected_product="rhel",
        rows=999,
        from_date="2019-05-05T22:00:00Z",
        sort_asc=True,
    )
    contains_9 = 0
    contains_8 = 0
    contains_90eus = 0
    for advisory in res:
        if advisory.affects_rhel_version_arch(9, None, Architecture.X86_64):
            print(f"{advisory.id} affects RHEL 9 x86_64")
            contains_9 += 1
        elif advisory.affects_rhel_version_arch(9, 0, Architecture.X86_64):
            print(f"{advisory.id} affects RHEL 9.0 EUS x86_64")
            contains_90eus += 1
        elif advisory.affects_rhel_version_arch(8, None, Architecture.X86_64):
            print(f"{advisory.id} affects RHEL 8 x86_64")
            contains_8 += 1
    print(f"Found {contains_9} advisories that affect RHEL 9 x86_64")
    print(f"Found {contains_8} advisories that affect RHEL 8 x86_64")
    print(f"Found {contains_90eus} advisories that affect RHEL 9.0 EUS x86_64")
    print(f"Found {len(res)} advisories in total")


if __name__ == "__main__":
    asyncio.run(main())
