from rest_framework.parsers import MultiPartParser
from rest_framework.exceptions import ParseError


class CustomMultipartParser(MultiPartParser):
    def parse(self, stream, media_type=None, parser_context=None):
        parser_context = parser_context or {}
        request = parser_context['request']
        encoding = parser_context['encoding']


        # Early termination for empty requests
        if not request.body:
            return {}

        # Proceed with standard parsing
        return super().parse(stream, media_type, parser_context)