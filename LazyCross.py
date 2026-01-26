import idaapi
import idautils
import idc

VERSION = "1.0.0"

ACTION_XREF = "lazycross:xref"

class XrefChoose(idaapi.Choose):
    def __init__(self, title, items):
        idaapi.Choose.__init__(self, title, [["Address", 30], ["Pseudocode line", 80]], embedded=False, width=100, icon=40)
        self.items = items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        item = self.items[n]
        return [idc.get_func_off_str(item["addr"]), item["line"]]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        idaapi.jumpto(self.items[n]["addr"])

class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)
        if form_type == idaapi.BWN_DISASM:
            ea = idaapi.get_screen_ea()
            if ea != idaapi.BADADDR:
                return
        idaapi.attach_action_to_popup(form, popup, ACTION_XREF, None)

def HexRaysCallback(event, *args):
    if event == idaapi.hxe_populating_popup:
        widget, phandle, vu = args
        if vu.item.get_ea() != idaapi.BADADDR:
            idaapi.attach_action_to_popup(widget, phandle, ACTION_XREF, None)
    return 0

class ActionHandler(idaapi.action_handler_t):
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE] else idaapi.AST_DISABLE_FOR_WIDGET

    def activate(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            vu = idaapi.get_widget_vdui(ctx.widget)
            ea = vu.item.get_ea()
        elif ctx.widget_type == idaapi.BWN_DISASM:
            ea = idaapi.get_screen_ea()
        else:
            return 0

        try:
            idaapi.show_wait_box("Processing...")
            show_xref(ea)
        except KeyboardInterrupt:
            print("LazyCross: User interrupted")
        finally:
            idaapi.hide_wait_box()

        return 0

class ObjVisitor(idaapi.ctree_visitor_t):
    def __init__(self, ea, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.found = []
        self.target_ea = ea
        self.cfunc = cfunc

    def visit_expr(self, expr):
        # check callee ea
        if expr.obj_ea != self.target_ea:
            return 0

        # find top expr
        e = expr
        addr = expr.ea
        while True:
            p = self.cfunc.body.find_parent_of(e)
            if not p or p.op > idaapi.cit_empty:
                break
            e = p
            if e.ea != idaapi.BADADDR:
                addr = e.ea

        self.found.append({
            "addr": addr,
            "line": idaapi.tag_remove(e.print1(None))
        })
        return 0

def show_xref(ea):
    name = idaapi.get_name(ea)
    demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    if demangled:
        name = demangled
    
    if not name:
        print(f"LazyCross: Invalid name")
        return
    
    print(f"LazyCross: Find cross reference to {name}...")

    found = []
    checked = []
    for ref in idautils.XrefsTo(ea, False):
        if idaapi.user_cancelled():
            raise KeyboardInterrupt

        frm = ref.frm
        if not idaapi.is_code(idaapi.get_flags(frm)):
            continue

        func = idaapi.get_func(frm)
        func_name = idaapi.get_func_name(frm)
        if not func:
            print(f"LazyCross: Reference is not from a function: 0x{frm:x}")
            continue

        if func.start_ea in checked:
            continue
        checked.append(func.start_ea)

        try:
            cfunc = idaapi.decompile(func)
        except idaapi.DecompilationFailure as e:
            print(f"LazyCross: Decompile {func_name} failed")
            print(str(e))
            continue

        if not cfunc:
            print(f"LazyCross: cfunc is none: {func_name}")
            continue

        cv = ObjVisitor(ea, cfunc)
        try:
            cv.apply_to(cfunc.body, None)
        except Exception as e:
            print(cfunc)
            print(e)
        found += cv.found

    if found:
        ch = XrefChoose(f"Cross references to {name}", found)
        ch.Show()
    else:
        print("LazyCross: No xrefs found")

class LazyCross(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "LazyCross"
    help = ""
    wanted_name = "LazyCross"
    wanted_hotkey = ""

    def init(self):
        self.hexrays_inited = False

        self.action = idaapi.action_desc_t(ACTION_XREF, "LazyCross", ActionHandler(ACTION_XREF), "Ctrl+X")
        idaapi.register_action(self.action)

        self.ui_hook = UI_Hook()
        self.ui_hook.hook()

        if idaapi.init_hexrays_plugin():
            addon = idaapi.addon_info_t()
            addon.id = "tw.l4ys.lazycross"
            addon.name = "LazyCross"
            addon.producer = "Lays"
            addon.url = "https://github.com/L4ys/LazyCross"
            addon.version = VERSION
            idaapi.register_addon(addon)

            idaapi.install_hexrays_callback(HexRaysCallback)
            self.hexrays_inited = True

        print(f"LazyCross ({VERSION}) plugin has been loaded.")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self.ui_hook.unhook()
        idaapi.unregister_action(self.action.name)

        if self.hexrays_inited:
            idaapi.remove_hexrays_callback(HexRaysCallback)
            idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return LazyCross()

