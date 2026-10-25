import binascii
import logging
import distorm3


def disassemble(path, offset, first_instr_offset, match_len, context_bytes, decoder):
    """
        Try to disassemble the context_bytes provided so that an instruction starts on the first byte of the yara match (first_instr_offset)
        Typically asm signatures should land this way.
    """
    for off in range(0, first_instr_offset):
        instructions = distorm3.Decode(offset+off, context_bytes[off:], decoder) 
        for instr in instructions:
            #If one of the instructions aligns with the first byte of the signature match, then our alignment is probably correct. Return result
            if instr[0] == offset + first_instr_offset:
                return render_disassembly(instructions, offset+first_instr_offset, match_len)
    # We failed to align an instruction with the signature match. Just disassemble from the start of context
    logging.debug('Failed to align disassembly with context: {} first byte offset: 0x{}'.format(binascii.hexlify(context_bytes), first_instr_offset))
    return render_disassembly(distorm3.Decode(offset, context_bytes, decoder), offset+first_instr_offset, match_len)

def render_disassembly(dis, match_offset, match_len, context_lines=4):
    """
        Accepts a DecodeGenerator from distorm and returns a string that will be directly rendered in the ICE yara results page
        dis: DecodeGenerator from distorm.Decode()
        match_offset: offset into the file where the match occured
        match_len: Length of yara  match
        context_lines: How many lines of disassembly to return before and after the matching lines
    """
    lines = []
    first_line = None
    last_line = None
    for i in range(len(dis)):
        instr = dis[i]
        asm = '0x{:08X}     {:<20}{}'.format(instr[0], instr[3], instr[2])
        if instr[0] >= match_offset and instr[0]  < match_offset+match_len:
            lines.append('<b>{}</b>'.format(asm))
            if not first_line:
                first_line = i
        else:
            lines.append(asm)
            if first_line and not last_line:
                last_line = i
    lines = lines[:first_line][-context_lines-1:] + lines[first_line:last_line] + lines[last_line:][:context_lines]
    logging.debug('Rendered disassembly: {}'.format('\n'.join(lines)))
    return '\n'.join(lines)