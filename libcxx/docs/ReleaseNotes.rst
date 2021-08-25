=========================================
Libc++ 14.0.0 (In-Progress) Release Notes
=========================================

.. contents::
   :local:
   :depth: 2

Written by the `Libc++ Team <https://libcxx.llvm.org>`_

.. warning::

   These are in-progress notes for the upcoming libc++ 14 release.
   Release notes for previous releases can be found on
   `the Download Page <https://releases.llvm.org/download.html>`_.

Introduction
============

This document contains the release notes for the libc++ C++ Standard Library,
part of the LLVM Compiler Infrastructure, release 14.0.0. Here we describe the
status of libc++ in some detail, including major improvements from the previous
release and new feature work. For the general LLVM release notes, see `the LLVM
documentation <https://llvm.org/docs/ReleaseNotes.html>`_. All LLVM releases may
be downloaded from the `LLVM releases web site <https://llvm.org/releases/>`_.

For more information about libc++, please see the `Libc++ Web Site
<https://libcxx.llvm.org>`_ or the `LLVM Web Site <https://llvm.org>`_.

Note that if you are reading this file from a Git checkout or the
main Libc++ web page, this document applies to the *next* release, not
the current one. To see the release notes for a specific release, please
see the `releases page <https://llvm.org/releases/>`_.

What's New in Libc++ 14.0.0?
============================

- Support for older compilers has been removed. Several additional platforms
  are now officially supported. :ref:`platform_and_compiler_support` contains
  the complete overview of platforms and compilers supported by libc++.
- The large headers ``<algorithm>``, ``<iterator>``, and ``<utility>`` have
  been split in more granular headers. This reduces the size of included code
  when using libc++. This may lead to missing includes after upgrading to
  libc++13.

New Features
------------

- ``std::filesystem`` is now feature complete for the Windows platform using
  MinGW. MSVC isn't supported since it lacks 128-bit integer support.
- The implementation of the C++20 concepts library has been completed.
- Several C++20 ``constexpr`` papers have been completed:

  - `P0879R0 <https://wg21.link/P0879R0>`_ ``constexpr`` for ``std::swap()``
    and swap related functions
  - `P1032R1 <https://wg21.link/P1032R1>`_ Misc ``constexpr`` bits
  - `P0883 <https://wg21.link/P0883>`_ Fixing Atomic Initialization

- More C++20 features have been implemented. :doc:`Status/Cxx20` has the full
  overview of libc++'s C++20 implementation status.
- More C++2b features have been implemented. :doc:`Status/Cxx2b` has the
  full overview of libc++'s C++2b implementation status.
- The CMake option ``LIBCXX_ENABLE_INCOMPLETE_FEATURES`` has been added. This
  option allows libc++ vendors to disable headers that aren't production
  quality yet. Currently, turning the option off disables the headers
  ``<format>`` and ``<ranges>``.
- The documentation conversion from html to restructured text has been
  completed.

API Changes
-----------

- ...
