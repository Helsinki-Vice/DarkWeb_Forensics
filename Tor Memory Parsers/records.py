from dataclasses import dataclass

@dataclass
class BrowserActivity:
    offset: int
    entry_type: str
    data: str

    def to_csv_row(self) -> list[str]:
        return [str(self.offset), self.entry_type, self.data]

@dataclass
class BrowserRequest:
    match_offset: int
    entry_type: str
    private_browsing_id: str
    first_party_domain: str
    requested_resource: str

    def to_csv_row(self) -> list[str]:
        return [str(self.match_offset), self.entry_type, self.private_browsing_id, self.first_party_domain, self.requested_resource]

@dataclass
class TabData:
    match_offset: int
    entry_type: str
    url: str
    title: str
    favicon_url: str

    def to_csv_row(self) -> list[str]:
        return [str(self.match_offset), self.entry_type, self.url, self.title, self.favicon_url]

@dataclass
class HttpRequest:
    match_offset: int
    entry_type: str
    method: str
    request_id: str
    url: str
    origin_url: str
    document_url: str
    request_type: str

    def to_csv_row(self) -> list[str]:
        return [str(self.match_offset), self.entry_type, self.method, self.request_id, self.url, self.origin_url, self.document_url, self.request_type]

@dataclass
class SocksRequest:
    match_offset: int
    entry_type: str
    tls_metadata: str
    url: str
    socks_info: str
    second_url: str
    private_browsing_id: str
    first_party_domain: str

    def to_csv_row(self) -> list[str]:
        return [str(self.match_offset), self.entry_type, self.entry_type, self.tls_metadata, self.url, self.socks_info, self.second_url, self.private_browsing_id, self.first_party_domain]