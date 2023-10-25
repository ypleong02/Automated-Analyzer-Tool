import pymysql
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

    def rationaled():
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



# Establish a connection to database
connection = pymysql.connect(
    host='127.0.0.1',
    user='root',
    password='@nSec0201!',
    db='cve',
    cursorclass=pymysql.cursors.DictCursor
)

# Retrive cve information
def get_cve(cve, project, tool_flag):
    with connection.cursor() as cursor:
        query = "call select_cve(%s,%s,%s)"
        parameters = (cve, project, tool_flag)
        cursor.execute(query, parameters)
        CVE = cursor.fetchone()
        # Return cve with *full information* and rationale
        return CVE


def check_if_cve_exist(cve, project) -> bool:
    with connection.cursor() as cursor:
        query = "call check_cve_exist(%s,%s)"
        parameters = (cve, project)
        cursor.execute(query, parameters)
        exist = cursor.fetchone()
        # Returns a boolean 1 or 0
        return exist['cve_count']


def create_new_blackduck_cve(Component, Version, Latest_version, CVE, Matching_type, CVE_publication_date, Object_compilation_date, Object, Object_full_path, CVSS, CVSS_vector, Vulnerability_URL, Project, Rationale, Impact, Result, Note
) -> None:
    with connection.cursor() as cursor:
        query = "call cve.Create_New_Blackduck_CVE(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        parameters = (Component, Version, Latest_version, CVE, Matching_type, CVE_publication_date, Object_compilation_date, Object, Object_full_path, CVSS, CVSS_vector, Vulnerability_URL, Project, Rationale, Impact, Result, Note)
        cursor.execute(query, parameters)
        connection.commit()


def create_new_scantist_cve(Library, Status, Library_version, Vulnerability_id, Criticality_id, Score, Description, File_path, Latest_component_version, Latest_library_version_release_date, Vulnerability_report_time, CWE_id, CWE_description, Component, Project, Rationale, Impact, Result, Note
) -> None:
    with connection.cursor() as cursor:
        query = "call cve.Create_New_Scantist_CVE(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        parameters = (Library, Status, Library_version, Vulnerability_id, Criticality_id, Score, Description, File_path, Latest_component_version, Latest_library_version_release_date, Vulnerability_report_time, CWE_id, CWE_description, Component, Project, Rationale, Impact, Result, Note)
        cursor.execute(query, parameters)
        connection.commit()

# Get CVE list
def get_all_cve_info():
    with connection.cursor() as cursor:
        query = "SELECT * FROM rationale_cve"
        cursor.execute(query)
        cve = cursor.fetchall()
        return cve

if __name__ == "__main__":
    pass