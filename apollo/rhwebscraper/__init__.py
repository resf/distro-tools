from typing import Optional
from dataclasses import dataclass

import aiohttp
from bs4 import BeautifulSoup


@dataclass
class RHWebAdvisoryFix:
    id: str
    description: str


@dataclass
class PartialRHWebAdvisory:
    name: str
    topic: Optional[str]
    fixes: Optional[list[RHWebAdvisoryFix]]


async def get_advisory_topic_and_fixes(
    advisory_name: str
) -> Optional[PartialRHWebAdvisory]:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"https://access.redhat.com/errata/{advisory_name}"
        ) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")

                topic = soup.select("div#topic > p")
                if topic:
                    topic = "\n\n".join([p.text for p in topic])

                parsed_fixes = []
                fixes = soup.select("div#fixes > ul > li")
                if fixes:
                    for fix in fixes:
                        bugzilla_id = fix.find("a").attrs.get("href"
                                                             ).split("id=")[1]
                        description = fix.find("a").next_sibling.text.strip(
                        ).removeprefix("- ")
                        parsed_fixes.append(
                            RHWebAdvisoryFix(bugzilla_id, description)
                        )

                return PartialRHWebAdvisory(advisory_name, topic, parsed_fixes)
            else:
                return None
