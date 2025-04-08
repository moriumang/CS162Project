#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

def main():
    """Run administrative tasks."""
    # Set the default settings module for the Django project
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Reputation.settings')
    
    # Check if we're in a virtual environment
    if 'virtualenv' not in sys.prefix.lower():
        print("Warning: You are not running in a virtual environment!")
        print("Please activate your virtual environment before proceeding.")
    
    try:
        # Import and execute Django's command-line utility
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    # Execute the command passed as arguments
    execute_from_command_line(sys.argv)

if __name__ == '__main__':
    main()
