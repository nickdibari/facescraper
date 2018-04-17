from bs4 import BeautifulSoup


class BaseParser(object):
    """
    Base parser which other section parsers inherit from. Each subclass must
    implement a `run` method, in which the logic for parsing that specific
    section data will live. Each parser must specify what section to parse.
    """

    # Facebook data directory names
    BASE_DIR = 'facebook_data'
    HTML_DIR = 'html'

    SECURITY_SECTION = 'security'
    SECTION_NAMES = (SECURITY_SECTION)

    def __init__(self, section):
        self._validate_inputs(section)

        self.section = section

    def _validate_inputs(self, section):
        if section not in self.SECTION_NAMES:
            raise ValueError(
                '{name} is not a valid section. Enter one of: {opts}'.format(
                    name=section,
                    opts=self.SECTION_NAMES
                )
            )

    def run(self):
        raise NotImplementedError(
            'Subclasses must implement their own run()'
        )


class SecurityParser(BaseParser):
    """
    Parser for security data
    """

    FIELD_NAME_INDEX = {
        'IP Addresses': 6,
    }

    SECURITY_FILE = 'security.htm'

    def __init__(self, output_type=None, output_dir=None):
        xargs = {
            'section': self.SECURITY_SECTION,
        }

        super(SecurityParser, self).__init__(**xargs)

        self.filename = '{base}/{sub}/{filename}'.format(
            base=self.BASE_DIR,
            sub=self.HTML_DIR,
            filename=self.SECURITY_FILE,
        )

    def _parse_ip_addresses(self):
        """
        Parse the known IP addresses section for a log of what addresses the
        user has logged in from
        :@return ip_data: (dict) Map of IP addresses assosciated with user
        """
        address_list = []
        print('Starting parse of known IP addresses')

        with open(self.filename) as html_file:
            soup = BeautifulSoup(html_file, 'html.parser')
            section_index = self.FIELD_NAME_INDEX['IP Addresses']
            ip_address_html = soup.find_all('ul')[section_index]

            for idx, address in enumerate(ip_address_html.find_all('li')):
                address_map = {}
                address_map['Index'] = idx
                address_map['IP Address'] = address.getText()

                address_list.append(address_map)

        return address_list

    def run(self):
        print('Starting parse of security data')

        ip_data = self._parse_ip_addresses()

        ip_packet = {
            'section': self.section,
            'subsection': 'ip_addresses',
            'data': ip_data,
            'fieldnames': ['Index', 'IP Address']
        }

        data = ip_packet

        return data
