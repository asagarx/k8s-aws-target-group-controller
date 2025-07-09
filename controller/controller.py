"""
Main controller module that initializes and runs the AWS Target Group operator.
"""

from . import handlers  # This will import and register all kopf handlers

# The handlers module contains all the kopf decorators and business logic
# The actual operator functionality is implemented in the imported modules