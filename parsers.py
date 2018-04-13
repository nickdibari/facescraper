from bs4 import BeautifulSoup


class BaseParser(object):
    """
    Base parser which other section parsers inherit from. The base class
    provides interfaces for outputting data in various formats and walking a
    directory to return files in the directory.

    Each subclass must implement a `run` method, in which the logic for
    parsing that specific section data will live.

    Each parser must specify what section to parse and what format to output
    the data as.
    """

    # Facebook data directory names
    BASE_DIR = 'facebook_data'
    HTML_DIR = 'html'

    # Facebook data file names
    SECURITY_FILE = 'security.htm'

    SECURITY_SECTION = 'security'
    SECTION_NAMES = (SECURITY_SECTION)

    CSV = 'csv'
    OUTPUT_TYPES = (CSV)
    OUTPUT_TYPE_EXTENSIONS = {
        CSV: '.csv',
    }

    def __init__(self, section, output_type):
        self._validate_inputs(section, output_type)

        self.section = section
        self.output_type = output_type

    def _validate_inputs(self, section, output_type):
        error_message = '{name} is not a valid input. Enter one of: {opts}'

        if section not in self.SECTION_NAMES:
            raise ValueError(
                error_message.format(name=section, opts=self.SECTION_NAMES)
            )

        if output_type not in self.OUTPUT_TYPES:
            raise ValueError(
                error_message.format(name=output_type, opts=self.OUTPUT_TYPES)
            )

    def _dump_to_csv(self, data):
        pass

    def dump(self, data):
        """
        Dump contents of data to specified output. Dynamically determine which
        output method to call and call the method. Important to note that
        future _dump_to methods should also include a corresponding entry in
        the OUTPUT_TYPE_EXTENSIONS dictionary and should follow the same
        naming convention.
        :param data: (list) List of dictionaries to dump to file
        """
        dump_method_name = '_dump_to_{ext}'.format(
            ext=self.output_type
        )

        getattr(self, dump_method_name)(data)


    def run(self):
        raise NotImplementedError('Subclasses must implement their own run()')


class SecurityParser(BaseParser):
    """
    Parser for security data
    """

    FIELD_NAME_INDEX = {
        'IP Addresses': 6,
    }

    def __init__(self, output_type=None):
        xargs = {
            'section': self.SECURITY_SECTION,
            'output_type': output_type or self.CSV,
        }

        super(SecurityParser, self).__init__(**xargs)
        self.filename = '{base}/{sub}/{section}'.format(
            base=self.BASE_DIR,
            sub=self.HTML_DIR,
            section=self.SECURITY_FILE
        )

    def _parse_ip_addresses(self):
        """
        Parse the known IP addresses section for a log of what addresses the
        user has logged in from
        :@return ip_data: (dict) Map of IP addresses assosciated with user
        """
        address_map = {}

        with open(self.filename) as html_file:
            soup = BeautifulSoup(html_file, 'html.parser')
            section_index = self.FIELD_NAME_INDEX['IP Addresses']
            ip_address_html = soup.find_all('ul')[section_index]

            for idx, address in enumerate(ip_address_html.find_all('li')):
                address_map[str(idx)] = address.getText()

        return address_map

    def run(self):
        pass
