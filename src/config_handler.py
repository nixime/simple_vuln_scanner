import configparser
import os
from openpyxl.utils.cell import column_index_from_string

class BaseConfig:
    """
    A foundational class for handling .ini file parsing with automatic type casting.
    """
    def __init__(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Could not find: {file_path}")
        self._parser = configparser.ConfigParser()
        self._parser.read(file_path)

    def _clean_value(self, value):
        """Removes surrounding quotes and whitespace."""
        return value.strip().strip('"').strip("'")

    def _cast_primitive(self, value):
        """Handles booleans, integers, and floats for any config type."""
        val_lower = value.lower()
        if val_lower in ['true', 'yes', 'on']: return True
        if val_lower in ['false', 'no', 'off']: return False

        try:
            return float(value) if '.' in value else int(value)
        except ValueError:
            return value

class NVDConfigFile(BaseConfig):
    """Parses INI files into nested objects"""
    def __init__(self, file_path):
        super().__init__(file_path)
        self._map_sections()

    def _map_sections(self):
        for section in self._parser.sections():
            data = {key: self._parse_logic(section, key, val) 
                    for key, val in self._parser.items(section)}
            # Creates a dynamic object from the dictionary
            section_obj = type(section, (object,), data)
            setattr(self, section, section_obj)

    def _parse_logic(self, section, key, value):
        value = self._clean_value(value)

        # Specialized List Logic
        if section.casefold() == "global" and key.casefold() == "input_configs":
            return [item.strip() for item in value.split(',')]

        # Specialized Excel Logic
        if section.casefold() == "template" and key.lower().startswith("column"):
            if not key.lower().endswith("value"):
                try:
                    return int(value)
                except ValueError:
                    return column_index_from_string(value)

        return self._cast_primitive(value)

class SystemConfigFile(BaseConfig):
    """Parses the first section of an INI file directly onto the class instance."""
    def __init__(self, file_path):
        super().__init__(file_path)
        self._map_sections()

    def _map_sections(self):
        # We assume the first section is the target "system"
        section_name = self._parser.sections()[0]
        self.system_name = section_name
        
        for key, val in self._parser.items(section_name):
            value = self._clean_value(val)
            # Specialized List Logic
            if key.casefold() == "boms":
                parsed_value = [item.strip() for item in value.split(',')]
            else:
                parsed_value = self._cast_primitive(value)
            
            setattr(self, key, parsed_value)