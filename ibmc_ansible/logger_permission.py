#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import os
import logging
import stat

from logging.handlers import RotatingFileHandler


class SetLogPermission(RotatingFileHandler):
    """
    Function :
        Rewrite the log generation function to set the log permission.
    Interface:
        None
    Date: 10/19/2019
    """

    def __init__(self, filename, mode="a", max_bytes=0,
                 backup_count=0, encoding=None, delay=False):
        try:
            super().__init__(filename, mode, max_bytes, backup_count, encoding,
                             delay)
        except TypeError:
            super(SetLogPermission, self).__init__(filename, mode, max_bytes,
                                                   backup_count, encoding,
                                                   delay)

    def rotate(self, source, dest):
        logging.handlers.RotatingFileHandler.rotate(self, source, dest)
        os.chmod(dest, stat.S_IRUSR)

    def _open(self):
        try:
            open_log = super()._open()
        except TypeError:
            open_log = super(SetLogPermission, self)._open()
        os.chmod(open_log.name, stat.S_IWUSR | stat.S_IRUSR)
        return open_log
