#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>

class IconExtractorError(Exception):
    """Superclass for exceptions raised by IconExtractor."""

class IconNotFoundError(IconExtractorError):
    """Exception raised when extracting an icon index or resource ID that does not exist."""

class NoIconsAvailableError(IconExtractorError):
    """Exception raised when the input program has no icon resources."""

class InvalidIconDefinitionError(IconExtractorError):
    """Exception raised when the input program has an invalid icon resource."""

class UnknownExecutableError(IconExtractorError):
    """Exception raised when the executable type is invalid or not supported."""
