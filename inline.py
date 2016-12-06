#!/usr/bin/env python
import os
import subprocess
import argparse

from elftools.elf.elffile import ELFFile


def get_attribute_value(die, attribute):
    attr = die.attributes.get(attribute)
    if attr is not None:
        return attr.value


def get_die_at_offset(cu, offset):
    adjusted_offset = cu.cu_offset + offset
    for die in cu.iter_DIEs():
        if die.offset == adjusted_offset:
            return die


def get_filename(cu, file_idx):
    if not file_idx:
        return None
    top_die = cu.get_top_DIE()
    dwarf = cu.dwarfinfo
    lp = dwarf.line_program_for_CU(cu)
    file_entry = lp.header.file_entry[file_idx - 1]
    filename = file_entry.name
    dir_index = file_entry.dir_index
    if dir_index:
        directory = lp.header.include_directory[dir_index - 1]
    else:
        directory = top_die.attributes['DW_AT_comp_dir'].value
    return os.path.normpath(os.path.join(directory, filename))


def get_coords_file(die, attr):
    if attr not in die.attributes:
        return None
    cu = die.cu
    file_idx = die.attributes[attr].value
    return get_filename(cu, file_idx)


def get_declaration_file(die):
    return get_coords_file(die, 'DW_AT_decl_file')


def get_declaration_coords(die):
    filename = get_declaration_file(die)
    line_no = get_attribute_value(die, 'DW_AT_decl_line')
    return filename, line_no


def get_die_call_file(die):
    return get_coords_file(die, 'DW_AT_call_file')


def get_die_call_coords(die):
    filename = get_die_call_file(die)
    line = die.attributes['DW_AT_call_line'].value
    return '%s:%i' % (filename, line)


def process(cu):
    for die in cu.iter_DIEs():
        if die.tag == 'DW_TAG_inlined_subroutine':
            offset = die.attributes['DW_AT_abstract_origin'].value
            origin = get_die_at_offset(die.cu, offset)
            while 'DW_AT_specification' in origin.attributes:
                offset = origin.attributes['DW_AT_specification'].value
                origin = get_die_at_offset(die.cu, offset)
            name = origin.attributes['DW_AT_name'].value
            coords = get_die_call_coords(die)
            print '%s inlined at %s' % (name, coords)


def iter_by_tag(cu, tag):
    for die in cu.iter_DIEs():
        if die.tag == tag:
            yield die


def iter_subprogram_dies(cu):
    return iter_by_tag(cu, 'DW_TAG_subprogram')


class cached_property(object):
    """
    Descriptor (non-data) for building an attribute on-demand on first use.
    """
    def __init__(self, factory):
        """
        <factory> is called such: factory(instance) to build the attribute.
        """
        self._attr_name = factory.__name__
        self._factory = factory

    def __get__(self, instance, owner):
        # Build the attribute.
        attr = self._factory(instance)

        # Cache the value; hide ourselves.
        setattr(instance, self._attr_name, attr)

        return attr


class FunctionInfo(object):
    def __init__(self, die):
        self.die = die

    def _get_attribute_recursive(self, name):
        attribute = self.die.attributes.get(name, None)
        if attribute:
            return attribute
        spec = self.specification
        if spec:
            return spec._get_attribute_recursive(name)
        return None

    def _get_attribute_value_recursive(self, name):
        attr = self._get_attribute_recursive(name)
        if attr:
            return attr.value
        else:
            return None

    @cached_property
    def name(self):
        return self._get_attribute_value_recursive('DW_AT_name')

    @cached_property
    def filename(self):
        file_idx = self._get_attribute_value_recursive('DW_AT_decl_file') or 0
        return get_filename(self.die.cu, file_idx)

    @cached_property
    def line(self):
        return self._get_attribute_value_recursive('DW_AT_decl_line')

    @cached_property
    def linkage_name(self):
        return self._get_attribute_value_recursive('DW_AT_linkage_name')

    def __hash__(self):
        return hash(self.linkage_name)

    @cached_property
    def cmp_tuple(self):
        return (self.filename, self.line, self.linkage_name)

    def __eq__(self, other):
        return self.cmp_tuple == other.cmp_tuple

    def __lt__(self, other):
        return self.cmp_tuple < other.cmp_tuple

    @cached_property
    def linkage_name_unmangled(self):
        return subprocess.check_output(['c++filt', self.linkage_name]).strip()

    @cached_property
    def inline_enum(self):
        return self._get_attribute_value_recursive('DW_AT_inline') or 0

    @cached_property
    def is_inlined(self):
        return self.inline_enum in (1, 3)

    @cached_property
    def declared_inline(self):
        return self.inline_enum in (2, 3)

    @cached_property
    def specification(self):
        # TODO: Handle all types of references
        offset = get_attribute_value(self.die, 'DW_AT_specification')
        if not offset:
            return None
        die = get_die_at_offset(self.die.cu, offset)
        if die:
            return FunctionInfo(die)
        else:
            print 'WARNING: No die at offset', offset


def iter_functions(cu):
    for die in iter_subprogram_dies(cu):
        yield FunctionInfo(die)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', nargs='?', default='a.out')
    parser.add_argument('--ignore', action='append', default=[])
    parser.add_argument('--demangle', action='store_true')
    parser.add_argument('--declaration', action='store_true')
    args = parser.parse_args()

    filename = args.filename
    ignore = tuple(args.ignore)

    with open(filename, 'rb') as input_file:
        elf = ELFFile(input_file)
        dwarf = elf.get_dwarf_info()

        def iter_inlined():
            for cu in dwarf.iter_CUs():
                # iterate over all functions
                functions = iter_functions(cu)
                # only include inlined functions
                functions = (func for func in functions if func.is_inlined)
                # skip functions with no filename assigned
                functions = (func for func
                             in functions
                             if func.filename)
                # skip ignored functions from ignored files
                if ignore:
                    functions = (func for func
                                 in functions
                                 if not func.filename.startswith(ignore))
                # skip unnamed functions
                functions = (func for func in functions if func.linkage_name)

                for func in functions:
                    yield func

        functions = sorted(set(iter_inlined()))

        for func in functions:
            if args.declaration:
                print '%s:%i' % (func.filename, func.line),
            if args.demangle:
                print func.linkage_name_unmangled
            else:
                print func.linkage_name


if __name__ == '__main__':
    main()
