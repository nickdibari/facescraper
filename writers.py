import os
from csv import DictWriter


class BaseWriter(object):
    """
    Base writer which other format writers inherit from. The base class
    contains interfaces to open a directory to write the data to. Each subclass
    is responsible for implenting a `dump` method which would write the data
    passed to it to the corresponding file format.
    """

    CSV = 'csv'
    OUTPUT_TYPES = (CSV)

    BASE_OUTPUT_DIR = 'data'

    def __init__(self, output_type, output_dir):
        self._validate_inputs(output_type)

        self.output_type = output_type
        self.output_dir = output_dir or self.OUTPUT_DIR

    def _validate_inputs(self, output_type):
        if output_type not in self.OUTPUT_TYPES:
            raise ValueError(
                '{name} is not a valid output. Enter one of: {opts}'.format(
                    name=output_type,
                    opts=self.OUTPUT_TYPES
                )
            )

    def dump(self, section_data):
        """
        Entry point to the CSVWriter class. Takes information/data about the
        section and writes to a CSV file.

        Section data should follow the schema (Fields in [] are optional):
            "subsection": Name of subsection being written
            "section": Name of section being written
            "data": Data to write to file
            ["fieldnames"]: List of headers to write to (Needed for CSV files)
        """
        raise NotImplementedError(
            'Subclasses must implement their own dump()'
        )


class CSVWriter(BaseWriter):
    def __init__(self, output_dir=None):
        xargs = {
            'output_type': self.CSV,
            'output_dir': output_dir or self.BASE_OUTPUT_DIR
        }

        super(CSVWriter, self).__init__(**xargs)

    def _dump_to_csv(self, section, subsection, data, fieldnames):
        """
        Actually write the output to the csv
        :param section: (str) Name of section passed to write data from
        :param subsection: (str) Name of the file to write to
        :param data: (list) List of dicts (CSV rows) to write to file
        :param fieldnames: (list) List of fieldnames to include in the CSV
        """
        print('Going to dump to CSV')

        dirname = '{dirname}/{section}'.format(
            dirname=self.output_dir,
            section=section,
        )

        if not os.path.exists(dirname):
            print('Creating directory: {}'.format(dirname))
            os.makedirs(dirname)

        filename = '{dirname}/{name}.{ext}'.format(
            dirname=dirname,
            name=subsection,
            ext=self.output_type
        )

        with open(filename, 'w') as csv_file:
            writer = DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()

            for row in data:
                writer.writerow(row)

        print('Done! Output is in {}'.format(filename))

    def dump(self, section_data):
        """
        Build data to send to helper method to dump section_data to CSV
        """
        for section in section_data:
            section_name = section['section']
            subsection = section['subsection']
            data = section['data']
            fieldnames = section['fieldnames']

            print('Dumping {section}-{subsection}'.format(
                section=section_name,
                subsection=subsection,
            ))

            self._dump_to_csv(section_name, subsection, data, fieldnames)
