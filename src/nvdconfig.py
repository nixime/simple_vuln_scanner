import configparser
import os
from openpyxl.utils.cell import column_index_from_string

class NVDConfigFile:
    def __init__(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Could not find: {file_path}")
        self._parser = configparser.ConfigParser()
        self._parser.read(file_path)
        self._map_sections()

    def _map_sections(self):
        for section in self._parser.sections():
            # Create a nested object for the section
            data = {key: self._parse_value(section, key, val) for key, val in self._parser.items(section)}
            section_obj = type(section, (object,), data)
            setattr(self, section, section_obj)

    def _parse_value(self, section, key, value):
        value = value.strip('"')
        value = value.strip("'")

        # Handle the specific array case (Case-insensitive check)
        if section.casefold() == "GLOBAL".casefold():
            if key.casefold() == "input_configs".casefold():
                return [item.strip() for item in value.split(',')]


        if section.casefold() == "TEMPLATE".casefold():
            if key.lower().startswith("column") and not key.lower().endswith("value"):
                try:
                    return(int(value))
                except ValueError:
                    return column_index_from_string(value)

        if value.lower() in ['true', 'yes', 'on']: return True
        if value.lower() in ['false', 'no', 'off']: return False

        try:
            if '.' in value: return float(value)
            return int(value)
        except ValueError:
            return value


class SystemConfigFile:
    def __init__(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Could not find: {file_path}")
        self._parser = configparser.ConfigParser()
        self._parser.read(file_path)
        self._map_sections()

    def _map_sections(self):
        section = self._parser.sections()[0]
        setattr(self,'system_name',section)
        
        for key, val in self._parser.items(section):
            parsed_value=self._parse_value(key, val)
            setattr(self, key, parsed_value)

    def _parse_value(self, key, value):
        value = value.strip('"')
        value = value.strip("'")

        if key.casefold() == "boms".casefold():
            return [item.strip() for item in value.split(',')]

        if value.lower() in ['true', 'yes', 'on']: return True
        if value.lower() in ['false', 'no', 'off']: return False

        try:
            if '.' in value: return float(value)
            return int(value)
        except ValueError:
            return value