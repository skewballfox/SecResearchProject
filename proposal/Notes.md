![](.assets/Pasted%20image%2020230905164411.png)

- [nsf proposal guidelines](https://mitcommlab.mit.edu/broad/commkit/nsf-research-proposal/)

## Introduce Research Idea

todo

### The plan

- gather data via [cwe2](https://pypi.org/project/cwe2/) or directly via API/scraper on [cwe-1399](https://cwe.mitre.org/data/definitions/1399.html), a comprehensive list of cwe's related to memory safety,
- use that to gather data to check against [nvdlib](https://nvdlib.com/en/latest/).
- gather information and statistical data on the findings, as well as the projects involved
- from there we can choose a few options:
  - if one of those vulnerabilities is part of a small self contained part of the codebase, write a rust lib that can be called via FFI in the native language. see how rust's memory model is or isn't beneficial
  - otherwise, priortize the 3 most damaging memory safety issues, using a function of prevalence and severity. Assess how memory safe languages address these(or don't).
    - potentially classify tasks in which it is better to rewrite sections in a memory safe lang which is called via FFI/c_bindings. this could help businesses prioritize resource allocation.

### Intellectual Merits and Broader Impact

> The following elements should be considered in the review for both criteria:
>
> 1. What is the potential for the proposed activity to:
>
> - Advance knowledge and understanding within its own field or across different fields (Intellectual Merit); and
>  - Benefit society or advance desired societal outcomes (Broader Impacts)?
>
#### Intellectual Merits
>
> The Intellectual Merit criterion encompasses the potential to advance knowledge;
>
#### Broader Impacts
>
> The Broader Impacts criterion encompasses the potential to benefit society and contribute to the achievement of specific, desired societal outcomes

- [list of activities that constitute broader impact](http://www.nsf.gov/pubs/2007/nsf07046/nsf07046.jsp)

- maybe a useful tool will come out of the data aggregation/analysis phase
-

## Research Plan

as a recap, here's the project the either suggested or used as an example:
>
## Logistics and Practicalities

todo
