import asyncio

from __init__ import get_advisory_topic_and_fixes


async def main():
    advisory = await get_advisory_topic_and_fixes("RHSA-2023:0536")
    print(advisory)


if __name__ == "__main__":
    asyncio.run(main())
