# pages/__init__.py
# Ce fichier rend le dossier 'pages' un package Python

from .detection_ia import display_detection_ia
from .correlation import display_correlation
from .recommandations import display_recommendations
from .investigation import display_investigation
from .configuration import display_configuration

__all__ = [
    'display_detection_ia',
    'display_correlation',
    'display_recommendations',
    'display_investigation',
    'display_configuration'
]