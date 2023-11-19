import nvdlib
import requests
from bs4 import BeautifulSoup, NavigableString
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
from pprint import pprint
from dataclasses import dataclass, field, InitVar
from enum import Enum
from serde import serde
from serde.json import to_json, from_json
from nvdlib.classes import CVE as nvdlib_CVE

data_dir = Path(__file__).parent.parent.parent / "data"


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
class CVE:
    id: str = ""
    cisa_vulnerability_name: str = ""
    url: str = ""
    description: str = ""

    references: List[Reference] = field(default_factory=list)
    configurations: List[Configurations] = field(default_factory=list)
    v31vector: str = ""
    v31score: float = 0.0
    v31severity: str = ""
    v31impactScore: float = 0.0
    v31exploitability: float = 0.0


def db_entry_to_cve(nvdlib_entry: Dict[Any, Any]) -> CVE:
    cve = CVE()

    for k, v in nvdlib_entry.items():
        match k:
            case "descriptions":
                print(v)
                for desc_entry in v:
                    if desc_entry.lang == "en":
                        print(desc_entry.value)
                cve.description = v
            case "configurations":
                for conf in v:
                    config = Configurations()
                    for node in conf.nodes:
                        if len(node.__dict__.keys()) > 3:
                            print("Warning: unhandled keys")
                            print(conf.__dict__.keys())
                        tmp = ConfNode(str(node.operator), bool(node.negate))

                        for x in node.cpeMatch:
                            if len(x.__dict__.keys()) > 5:
                                print("Warning: unhandled keys")
                                print(x.__dict__.keys())
                            if len(x.__dict__.keys()) < 5:
                                print("Warning: missing keys")
                                print(x.__dict__.keys())
                            tmp.cpeMatch.append(
                                CPEmatch(
                                    bool(x.vulnerable),
                                    str(x.criteria),
                                    str(x.versionStartIncluding)
                                    if hasattr(x, "versionStartIncluding")
                                    else None,
                                    str(x.versionEndExcluding)
                                    if hasattr(x, "versionEndExcluding")
                                    else None,
                                    str(x.matchCriteriaId),
                                )
                            )
                        config.nodes.append(tmp)
                    cve.configurations.append(config)
            case "v31vector":
                cve.v31vector = str(v)
            case "v31score":
                cve.v31score = float(v)

            case "v31severity":
                cve.v31severity = str(v)
            case "v31impactScore":
                cve.v31impactScore = float(v)
            case "v31exploitability":
                cve.v31exploitability = float(v)
            case "references":
                for ref in v:
                    cve.references.append(
                        Reference(
                            ref.url,
                            [str(tag) for tag in ref.tags]
                            if hasattr(ref, "tags")
                            else [],
                        )
                    )
            case default:
                continue
    return cve


def get_cve_data(cve_id: str, data_path: Path = data_dir) -> CVE:
    """
    Returns a CVE object for the given CVE ID.
    Parameters
    ----------
    cve_id : str
        The CVE ID to search for
    data_path : Path
        The path to the data directory, by default it is {project_root}/data
    """
    if (data_path / f"{cve_id}.json").exists():
        with open(data_path / f"{cve_id}.json", "r") as f:
            return from_json(CVE, json.load(f))
    else:
        cve_data = nvdlib.searchCVE(cveId=cve_id)
        cve = db_entry_to_cve(cve_data.__dict__)
        with open(data_path / f"{cve_id}.json", "w") as f:
            json.dump(to_json(cve), f)
        return cve
