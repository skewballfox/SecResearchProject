from cwe2.database import Database
import nvdlib
import requests
from bs4 import BeautifulSoup, NavigableString
from pathlib import Path
from typing import List, Optional
import json
from pprint import pprint
from dataclasses import dataclass, field
from enum import Enum
from serde import serde
from serde.json import to_json, from_json

cwe_base_url = "https://cwe.mitre.org/data/definitions/"

data_dir = Path(__file__).parent.parent.parent / "data"
print(data_dir)


class wtype(str, Enum):
    """The classification of a CWE, does not include view or category"""

    CLASS = "Class"
    """a weakness that is described in a very abstract fashion, typically independent of any specific language or
    technology. More specific than a Pillar Weakness, but more general than a Base Weakness. Class level weaknesses 
    typically describe issues in terms of 1 or 2 of the following dimensions: behavior, property, and resource."""

    BASE = "Base"
    """a weakness that is still mostly independent of a resource or technology, but with sufficient details to provide
    specific methods for detection and prevention. Base level weaknesses typically describe issues in terms of 2 or 3
    of the following dimensions: behavior, property, technology, language, and resource."""

    VARIANT = "Variant"
    """ a weakness that is linked to a certain type of product, typically involving a specific language or technology.
    More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the
    following dimensions: behavior, property, technology, language, and resource."""

    Chain = "Chain"
    """ a Compound Element that is a sequence of two or more separate weaknesses that can be closely linked together
    within software. One weakness, X, can directly create the conditions that are necessary to cause another 
    weakness, Y, to enter a vulnerable condition. When this happens, CWE refers to X as "primary" to Y, and Y is 
    "resultant" from X. Chains can involve more than two weaknesses, and in some cases, they might have a tree-like
    structure."""


@dataclass
class CVD:
    name: str
    description: str
    url: str


@serde
@dataclass
class CWE:
    id: int
    weakness_type: wtype
    name: str
    associated_cves: List[CVD] = field(default_factory=list)

    def __post_init__(self):
        if self.associated_cves:
            return
        self.associated_cves = []
        cwe_page = BeautifulSoup(
            requests.get(f"{cwe_base_url}{self.id}.html").text, "html5lib"
        )
        cves = []
        observed_cves = cwe_page.find(name="div", attrs={"id": "Observed_Examples"})
        if observed_cves is not None:
            for row in observed_cves.findAll(name="tr")[1:]:  # type: ignore
                (name_col, description_col) = row.findAll(name="td")
                if name_col and description_col:
                    cves.append(
                        CVD(
                            name=name_col.text,
                            description=description_col.text,
                            url=name_col.find(name="a").attrs["href"],
                        )
                    )
        self.associated_cves = cves


def get_mem_safe_cwes(data_path: Path = data_dir, overwrite: bool = False) -> List[CWE]:
    """
    Returns a list of CWEs that are related to memory safety.
    Parameters
    ----------
    data_path : Path
        The path to the data directory, by default it is {project_root}/data
    overwrite : bool
        Whether to overwrite the existing data file, by default False
    """
    cwes: List[CWE] = []
    if not overwrite and (data_path / "cwes.json").exists():
        return from_json(List[CWE], (data_path / "cwes.json").read_text())

    cwe_1399 = BeautifulSoup(
        requests.get("https://cwe.mitre.org/data/definitions/1399.html").text,
        "html5lib",
    )
    cwe_1399 = cwe_1399.find(name="table", attrs={"id": "Detail"})

    if cwe_1399 is None:
        raise Exception("Could not find table with id 'Detail' in CWE-1399 page")
    # first row is header, second is member of
    # rest are cwes
    for row in cwe_1399.findAll(name="tr")[2:]:  # type: ignore
        (_, type_col, id_col, name_col) = row.findAll(name="td")
        cwes.append(
            CWE(
                id=int(id_col.text),
                weakness_type=wtype(type_col.text.split(" ")[0]),
                name=name_col.text,
            )
        )
    data_path.mkdir(parents=True, exist_ok=True)
    (data_dir / "cwes.json").write_text(to_json(cwes, data_path / "cwes.json"))
    return cwes


if __name__ == "__main__":
    print(get_mem_safe_cwes(overwrite=True))
