"""Tests for the shared typed engine errors."""

from __future__ import annotations

from backend import errors

_ERROR_NAMES = (
    "CaptureError",
    "CorruptCaptureError",
    "UnsupportedFormatError",
    "DissectionError",
    "StorageError",
    "FilterError",
    "FilterSyntaxError",
)


def test_every_engine_error_shares_one_base():
    for name in _ERROR_NAMES:
        assert issubclass(getattr(errors, name), errors.MiniSharkError)


def test_specialised_errors_keep_their_group():
    assert issubclass(errors.CorruptCaptureError, errors.CaptureError)
    assert issubclass(errors.UnsupportedFormatError, errors.CaptureError)
    assert issubclass(errors.FilterSyntaxError, errors.FilterError)
    assert not issubclass(errors.FilterError, errors.CaptureError)
    assert not issubclass(errors.StorageError, errors.CaptureError)
