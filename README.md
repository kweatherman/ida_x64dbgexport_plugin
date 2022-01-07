# IDA x64dbgExport

A binary x64dbg debugger export plugin for IDA Pro.

A binary plugin version of mrexodia's official Python version: https://github.com/x64dbg/x64dbgida, 
but only with an export, no  "import" option.

## Installation

Copy `IDA_x64dbExport32.dll` and `IDA_x64dbExport64.dll` to your IDA `plugins` directory.
Requires IDA Pro 7.6'ish.

## Menu options

### Export database

Under the IDA "Edit menu". Export comments/labels/breakpoints to a JSON database that can be loaded by
x64dbg.

The "Demangle" option is experimental. The idea is that labels like `??1wxOverlay@@QEAA@XZ` would be easier to read as the demangled/undecorated version `wxOverlay::~wxOverlay(void)` for example. Problem though is that you will loose the ability to use the name as a symbol in x64dbg; thus no more jumping to or setting a break point on them by name.
After this experiment, it's obvious the right way to do this is to add it to x64dbg itself with a configurable display option so that demangled names can be displayed in the "CPU" view et al.

## Motivation

The original IDA Python plugin works functionally just fine. The problem is that for a very large 400K+ function executable I was working with, it took over a minute for the export. In this binary plugin form, with carful attention to the JSON file write throughput, etc., export time was reduced to a more manageable 13 seconds (a ~5x speed improvement).                                                                                                                                                                                                                                                                                                                                    

## Credits

Thanks to *mrexodia* for the awesome x64dbg debugger and the original export Python.

## License

Per the original Python version, released under MIT © 2022 By Kevin Weatherman
