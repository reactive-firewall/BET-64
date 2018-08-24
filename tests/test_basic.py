#! /usr/bin/env python
# -*- coding: utf-8 -*-

# BET-64 Tool
# ..................................
# Copyright (c) 2018, Kendrick Walls
# ..................................
# Licensed under MIT (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# ..........................................
# http://www.github.com/reactive-firewall/BET-64/LICENSE.md
# ..........................................
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest


class BasicTestSuite(unittest.TestCase):
	"""Basic test cases."""

	def test_absolute_truth_and_meaning(self):
		"""Insanitty Test. Because it only matters if we're not mad as hatters."""
		assert True

	def setUp(self):
		"""Insanity Test for unittests assertion."""
		self.assertTrue(True)
		self.assertFalse(False)
		self.assertIsNone(None)

	def test_syntax(self):
		"""Test case importing BET64."""
		theResult = False
		try:
			from .context import BET64
			self.assertIsNotNone(BET64.__name__)
			if BET64.__name__ is None:
				theResult = False
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult

	def test_the_help_command(self):
		"""Test case for backend library."""
		theResult = False
		try:
			from .context import BET64
			self.assertIsNotNone(BET64.__name__)
			if BET64.__name__ is None:
				theResult = False
			with self.assertRaises(Exception):
				raise RuntimeError("This is a test")
			with self.assertRaises(Exception):
				BET64.main(["--help"])
			theResult = True
		except Exception:
			theResult = False
		assert theResult

	def test_the_version_command(self):
		"""Test case for backend library."""
		theResult = False
		try:
			from .context import BET64
			self.assertIsNotNone(BET64.__name__)
			if BET64.__name__ is None:
				theResult = False
			with self.assertRaises(Exception):
				BET64.main(["--version"])
			theResult = True
		except Exception:
			theResult = False
		assert theResult

	def test_corner_case_example(self):
		"""Example Test case for bad input directly into function."""
		theResult = False
		try:
			from .context import BET64
			if BET64.__name__ is None:
				theResult = False
			from BET64 import BET64 as BET64
			self.assertIsNone(BET64.useTool(None))
			self.assertIsNone(BET64.useTool("JunkInput"))
			theResult = True
		except Exception:
			theResult = False
		assert theResult


# leave this part
if __name__ == '__main__':
	unittest.main()
