# -*- coding: utf-8 -*-

# Python Repo Template
# ..................................
# Copyright (c) 2017-2018, Kendrick Walls
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
except Exception as ImportErr:
	ImportErr = None
	del ImportErr
	raise ImportError(str("BET-64 Failed to Import"))


try:
	if 'BET64.BET64' not in sys.modules:
		from . import BET64 as BET64
	else:
		BET64 = sys.modules["""BET64.BET64"""]
except Exception:
	import BET64 as BET64


if __name__ in '__main__':
	if BET64.__name__ is None:
		raise ImportError(str("Failed to open BET-64"))
	BET64.main(sys.argv[1:])
	exit(0)
