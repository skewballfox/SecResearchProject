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
class Reference:
    url: str
    tags: List[str]


@dataclass
class CPEmatch:
    vulnerable: bool
    criteria: str
    versionStartIncluding: Optional[str]
    versionEndExcluding: Optional[str]
    matchCriteriaId: str


@dataclass
class ConfNode:
    operator: str
    negate: bool
    cpeMatch: List[CPEmatch] = field(default_factory=list)


@dataclass
class Configurations:
    nodes: List[ConfNode] = field(default_factory=list)


@dataclass
class CVD:
    id: str
    cisa_vulnerability_name: str
    url: str
    description: str = ""
    references: List[Reference] = field(default_factory=list)
    configurations: List[Configurations] = field(default_factory=list)
    v31vector: str = ""
    v31score: float = 0.0
    v31severity: str = ""
    v31impactScore: float = 0.0
    v31exploitability: float = 0.0

    def __post_init__(self):
        tmp = dict(nvdlib.searchCVE(cveId=self.id)[0].__dict__)
        for k, v in tmp.items():
            match k:
                case "descriptions":
                    print(v)
                    for desc_entry in v:
                        if desc_entry.lang == "en":
                            print(desc_entry.value)
                    self.description = v
                case "configurations":
                    for conf in v:
                        config = Configurations()
                        for node in conf.nodes:
                            if len(node.__dict__.keys()) > 3:
                                print("Warning: unhandled keys")
                                print(conf.__dict__.keys())
                            tmp = ConfNode(node.operator, node.negate)

                            for x in node.cpeMatch:
                                if len(x.__dict__.keys()) > 5:
                                    print("Warning: unhandled keys")
                                    print(x.__dict__.keys())
                                if len(x.__dict__.keys()) < 5:
                                    print("Warning: missing keys")
                                    print(x.__dict__.keys())
                                tmp.cpeMatch.append(
                                    CPEmatch(
                                        x.vulnerable,
                                        x.criteria,
                                        x.versionStartIncluding
                                        if hasattr(x, "versionStartIncluding")
                                        else None,
                                        x.versionEndExcluding
                                        if hasattr(x, "versionEndExcluding")
                                        else None,
                                        x.matchCriteriaId,
                                    )
                                )
                            config.nodes.append(tmp)
                        self.configurations.append(config)
                case "v31vector":
                    self.v31vector = v
                case "v31score":
                    self.v31score = v

                case "v31severity":
                    self.v31severity = v
                case "v31impactScore":
                    self.v31impactScore = v
                case "v31exploitability":
                    self.v31exploitability = v
                case "references":
                    for ref in v:
                        self.references.append(
                            Reference(
                                ref.url,
                                [str(tag) for tag in ref.tags]
                                if hasattr(ref, "tags")
                                else [],
                            )
                        )


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
                            id=name_col.text,
                            cisa_vulnerability_name=description_col.text,
                            url=f"https://nvd.nist.gov/vuln/detail/{name_col.text}",
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
    if not overwrite and (data_path / "cwes2.json").exists():
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
    (data_dir / "cwes2.json").write_text(to_json(cwes, data_path / "cwes.json"))
    return cwes


if __name__ == "__main__":
    print(get_mem_safe_cwes(overwrite=True))
