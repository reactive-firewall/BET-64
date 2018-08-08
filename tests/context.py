# -*- coding: utf-8 -*-

# BET-64 Tools
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


try:
	import sys
	import os
	if 'BET64' in __file__:
		sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
except Exception as ImportErr:
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	ImportErr = None
	del ImportErr
	raise ImportError("BET-64 Tool Failed to Import")


try:
	import BET64 as BET64
	if BET64.__name__ is None:
		raise ImportError("Failed to import BET-64.")
except Exception as importErr:
	importErr = None
	del importErr
	raise ImportError("Test module failed to load BET-64 for test.")
	exit(0)
