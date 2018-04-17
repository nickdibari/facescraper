from parsers import SecurityParser
from writers import CSVWriter

parser = SecurityParser()

data = parser.run()

writer = CSVWriter()

writer.dump(data)
