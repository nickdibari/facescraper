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
        'Recognized Machines': 3,
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

    def _parse_recognized_machines(self):
        """
        Parse the recognized machines section for a log of what machines are
        assosciated with the user profile
        :@return machine_data: (dict) Map of machines assosciated with user
        """
        machine_list = []
        print('Starting parse of recogined machines')

        with open(self.filename) as html_file:
            soup = BeautifulSoup(html_file, 'html.parser')
            section_index = self.FIELD_NAME_INDEX['Recognized Machines']
            recognized_machines_html = soup.find_all('ul')[section_index]

            for record in recognized_machines_html.find_all('p'):
                record_data = {}
                # The content of the recongized machine section is one
                # <p> for each machine with <br>'s in between. This method
                # will create a generator of strings from the tag and create a
                # map of fieldnames for each field in the record
                for field in record.strings:
                    fieldname, content = field.split(':', 1)
                    record_data[fieldname] = content
                    machine_list.append(record_data)

        return machine_list

    def run(self):
        print('Starting parse of security data')

        ip_data = self._parse_ip_addresses()

        ip_packet = {
            'section': self.section,
            'subsection': 'ip_addresses',
            'data': ip_data,
            'fieldnames': ['Index', 'IP Address']
        }

        machine_data = self._parse_recognized_machines()

        machine_packet = {
            'section': self.section,
            'subsection': 'recognized_machines',
            'data': machine_data,
            'fieldnames': [
                'IP Address', 'Updated', 'Browser', 'Created', 'Cookie'
            ]
        }

        data = [ip_packet, machine_packet]

        return data
