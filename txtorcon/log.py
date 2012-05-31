"""
This module handles txtorcon debug messages.
"""

from twisted.python import log as twlog

__all__ = ['txtorlog']

DEBUG = False


txtorlog = twlog.LogPublisher()

if DEBUG:
    stdobserver = twlog.PythonLoggingObserver('txtorcon')
    fileobserver = twlog.FileLogObserver(open('txtorcon.log', 'w'))

    txtorlog.addObserver(stdobserver.emit)
    txtorlog.addObserver(fileobserver.emit)
