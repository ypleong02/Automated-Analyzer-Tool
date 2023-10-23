from datetime import datetime

class blackduck_cve():
    
    def __init__(
            self,
            component: str = "",
            version: str = "",
            latest_version: str = "",
            cve: str = "",
            matching_type: str = "",
            cve_publication_date: datetime = "",
            object_compilation_date: datetime = "",
            object: str = "",
            object_full_path: str = "",
            cvss: float = "",
            cvss_vector: str = 0,
            vurnerability_url: str = "",
            project: str = "",
            rationale: str = "",
            impact: str = "",
            result: str = "",
            note: str = ""
            ) -> None:
        
        self.component = component
        self.version = version
        self.latest_version = latest_version
        self.cve = cve
        self.matching_type = matching_type
        self.cve_publication_date = cve_publication_date
        self.object_compilation_date = object_compilation_date
        self.object = object
        self.object_full_path = object_full_path
        self.cvss = cvss
        self.cvss_vector = cvss_vector
        self.vurnerability_url = vurnerability_url
        self.project = project
        self.rationale = rationale
        self.impact = impact
        self.result = result
        self.note = note

    def rationale():
        pass


class scantist_cve():

    def __init__(
            self,
            library: str = "",
            status: str = "",
            library_version: str = "",
            vulnerability_id: str = "",
            criticality: str = "",
            score: float = 0,
            description: str = "",
            file_path: str = "",
            latest_component_version: str = "",
            latest_library_version_release_date: str = "",
            vulnerability_report_time: str = "",
            cwe_id: str = "",
            cwe_description: str = "",
            component: str = "",
            project: str = "",
            rationale: str = "",
            impact: str = "",
            result: str = "",
            note: str = ""
            ) -> None:
        
        self.library = library
        self.status = status
        self.library_version = library_version
        self.vulnerability_id = vulnerability_id
        self.criticality = criticality
        self.score = score
        self.description = description
        self.file_path = file_path
        self.latest_component_version = latest_component_version
        self.latest_library_version_release_date = latest_library_version_release_date
        self.vulnerability_report_time = vulnerability_report_time
        self.cwe_id = cwe_id
        self.cwe_description = cwe_description
        self.component = component
        self.project = project
        self.rationale = rationale
        self.impact = impact
        self.result = result
        self.note = note
