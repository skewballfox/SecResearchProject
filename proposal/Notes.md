![](.assets/Pasted%20image%2020230905164411.png)

- [nsf proposal guidelines](https://mitcommlab.mit.edu/broad/commkit/nsf-research-proposal/)
- [annotated example 1](https://mitcommlab.mit.edu/broad/wp-content/uploads/sites/5/2016/09/Broad_CommKit_NSF-Research_Proposal_AAE1.pdf)
- [annotated example 2 (provided by Dr. Mittal)](https://mitcommlab.mit.edu/broad/wp-content/uploads/sites/5/2016/09/Broad_CommKit_NSF-Research_Proposal_AAE2.pdf)

if it's quoted, it's information they provided, otherwise it's information we're planning to include in the proposal

## Introduce Research Idea

todo



### Intellectual Merits and Broader Impact

> The following elements should be considered in the review for both criteria:
>
> 1. What is the potential for the proposed activity to:
>
> - Advance knowledge and understanding within its own field or across different fields (Intellectual Merit); and
> - Benefit society or advance desired societal outcomes (Broader Impacts)?
>
#### Intellectual Merits
>
> The Intellectual Merit criterion encompasses the potential to advance knowledge;
>
#### Broader Impacts
>
> The Broader Impacts criterion encompasses the potential to benefit society and contribute to the achievement of specific, desired societal outcomes

- [list of activities that constitute broader impact](http://www.nsf.gov/pubs/2007/nsf07046/nsf07046.jsp)

- maybe a useful tool will come out of the data aggregation/analysis phase. 
- might help projects prioritize areas where it's best to *bite the bullet* in the smallest scope possible.
- hopefully will help add to the body of evidence that we really, really should move to something that isn't C/C++

## Research Plan

as a recap, here's the project the either suggested or used as an example:
> 1. Work through the Common Weakness Enumeration (CWE) and identify weaknesses that are founded on abuse of memory issues (e.g. CWE-121).
> 2. Survey popular memory-safe languages and identify 2-3 for further study based on their ability to support low-level and system programming. Survey computer science literature to identify critical features of these languages.
>3. Survey the National Vulnerability Database to identify a representative set of low-level software vulnerabilities, reflecting the weaknesses collected in Step 1. For each vulnerability, attempt to characterize the subject software language and whether use of a memory-safe language would have detected/prevented the vulnerability.
> 4. Using the results from steps 1, 2 & 3, code up examples of each weakness in C or C++, and then write equivalent code in the identified memory-safe languages. Confirm or deny effectiveness of the languages in preventing exploitable vulnerabilities.

### Our Plan

- gather data via [cwe2](https://pypi.org/project/cwe2/) or directly via API/scraper on [cwe-1399](https://cwe.mitre.org/data/definitions/1399.html), a comprehensive list of cwe's related to memory safety,
- use that to gather data to check against [nvdlib](https://nvdlib.com/en/latest/).
- gather information and statistical data on the findings, as well as the projects involved
- from there we can choose a few options:
  - if one of those vulnerabilities is part of a small self contained part of the codebase, write a rust lib that can be called via FFI in the native language. see how rust's memory model is or isn't beneficial
  - otherwise, priortize the 3 most damaging memory safety issues, using a function of prevalence and severity. Assess how memory safe languages address these(or don't).
    - potentially classify tasks in which it is better to rewrite sections in a memory safe lang which is called via FFI/c_bindings. this could help businesses prioritize resource allocation.
## Logistics and Practicalities

todo

## Conclusion
## Citations

todo
### They originally provided
- [Software Memory Safety Cybersecurity Information Sheet](https://media.defense.gov/2022/Nov/10/2003112742/-1/-1/0/CSI_SOFTWARE_MEMORY_SAFETY.PDF)
- [Shift to Memory-Safe Languages Gains Momentum](https://www.darkreading.com/application-security/shift-memory-safe-languages-gains-momentum)
- [Safe Low-Level Code Without Overhead is Practical](https://ieeexplore.ieee.org/abstract/document/10172739)
- just a link to cwe website
### Can't use it but can mine it
- [reddit post aksing what cves could have bee prevented with rust](https://www.reddit.com/r/rust/comments/y935fn/what_bigname_cves_would_rust_have_helped_prevent/)

