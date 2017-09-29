// Aaron Eppert - 2017
// golang wrapper around libkmod
package gokmod

/*
#cgo pkg-config: libkmod
#include <libkmod.h>
*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

const (
	KMOD_FILTER_BUILTIN = 0x00002
)

type KModInfoParm struct {
	Desc string `json:"desc,omitempty"`
	Type string `json:"type,omitemtpy"`
}

type KModInfoParmMap map[string]*KModInfoParm
type KModInfoMap map[string][]string

// KModInfo - Kernel Module Info
type KModInfo struct {
	Info KModInfoMap     `json:"info,omitempty"`
	Parm KModInfoParmMap `json:"parm,omitempty"`
}

// KModList - Kernel Module List
type KModList struct {
	Name     string   `json:"name,omitempty"`
	Size     int      `json:"size,omitempty"`
	UseCount int      `json:"usecount,omitempty"`
	Holders  []string `json:"holders,omitempty"`
	Info     KModInfo `json:"info,omitempty"`
}

func utsArrayToStr(in []int8) string {
	i, out := 0, make([]byte, 0, len(in))
	for ; i < len(in); i++ {
		if in[i] == 0 {
			break
		}
		out = append(out, byte(in[i]))
	}
	return string(out)
}

func uname() (*syscall.Utsname, error) {
	uts := &syscall.Utsname{}

	if err := syscall.Uname(uts); err != nil {
		return nil, err
	}
	return uts, nil
}

func isModuleFilename(name string) bool {
	fi, err := os.Stat(name)
	if err != nil && fi != nil {
		if fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func modinfoDo(mod *C.struct_kmod_module) (KModInfo, error) {
	var list *C.struct_kmod_list
	var ret KModInfo
	ret.Info = make(KModInfoMap)
	ret.Parm = make(KModInfoParmMap)

	err := C.kmod_module_get_info(mod, &list)
	if err < 0 {
		return KModInfo{}, fmt.Errorf("could not get modinfo: %s", C.GoString(C.kmod_module_get_name(mod)))
	}

	for l := list; l != nil; l = C.kmod_list_next(list, l) {
		key := C.GoString(C.kmod_module_info_get_key(l))
		value := C.GoString(C.kmod_module_info_get_value(l))

		if key == "parm" || key == "parmtype" {
			parmkv := strings.Split(value, ":")
			parmkvKey := parmkv[0]
			parmkvVal := parmkv[1]

			if ret.Parm[parmkvKey] == nil {
				ret.Parm[parmkvKey] = &KModInfoParm{}
			}

			if key == "parm" {
				ret.Parm[parmkvKey] = &KModInfoParm{Desc: parmkvVal}
			}

			if key == "parmtype" {
				ret.Parm[parmkvKey].Type = parmkvVal
			}
			continue
		}

		ret.Info[key] = append(ret.Info[key], value)
	}

	C.kmod_module_info_free_list(list)

	return ret, nil
}

func modinfoPathDo(ctx *C.struct_kmod_ctx, path string) (KModInfo, error) {
	var mod *C.struct_kmod_module

	errInt := C.kmod_module_new_from_path(ctx, C.CString(path), &mod)
	if errInt < 0 {
		return KModInfo{}, errors.New("module file not found")
	}

	kmi, err := modinfoDo(mod)
	C.kmod_module_unref(mod)

	return kmi, err
}

func modinfoAliasDo(ctx *C.struct_kmod_ctx, alias string) (KModInfo, error) {
	var list *C.struct_kmod_list
	var filtered *C.struct_kmod_list
	var kmi KModInfo
	var err error

	errInt := C.kmod_module_new_from_lookup(ctx, C.CString(alias), &list)
	if errInt < 0 {
		return KModInfo{}, fmt.Errorf("module alias %s not found", alias)
	}

	if list == nil {
		return KModInfo{}, fmt.Errorf("module %s not found", alias)
	}

	errInt = C.kmod_module_apply_filter(ctx, KMOD_FILTER_BUILTIN, list, &filtered)
	C.kmod_module_unref_list(list)
	if errInt < 0 {
		return KModInfo{}, fmt.Errorf("failed to filter list")
	}

	if filtered == nil {
		return KModInfo{}, fmt.Errorf("module %s not found", alias)
	}

	for l := filtered; l != nil; l = C.kmod_list_next(filtered, l) {
		mod := C.kmod_module_get_module(l)
		kmi, err = modinfoDo(mod)
		C.kmod_module_unref(mod)
	}
	C.kmod_module_unref_list(filtered)

	return kmi, err
}

func getModInfo(ctx *C.struct_kmod_ctx, name string) (KModInfo, error) {
	var kmi KModInfo
	var err error

	if isModuleFilename(name) {
		kmi, err = modinfoPathDo(ctx, name)
	} else {
		kmi, err = modinfoAliasDo(ctx, name)
	}

	return kmi, err
}

// GetKModList - Get Kernel Module Information
//
// Argument:
// modinfo - bool - Pull module information
//
// Returns:
// []KModList on Success
// error != nil on failure
//
func GetKModList(modinfo bool) ([]KModList, error) {
	var ret []KModList
	var err error
	ctx := C.kmod_new(nil, nil)

	if ctx == nil {
		return nil, fmt.Errorf("could not obtain kmod context")
	}

	var list *C.struct_kmod_list
	errVal := C.kmod_module_new_from_loaded(ctx, &list)
	if errVal < 0 {
		C.kmod_unref(ctx)
		return nil, fmt.Errorf("could not get list of modules")
	}

	for itr := list; itr != nil; itr = C.kmod_list_next(list, itr) {
		var modEntry KModList

		mod := C.kmod_module_get_module(itr)
		modEntry.Name = C.GoString(C.kmod_module_get_name(mod))
		modEntry.UseCount = int(C.kmod_module_get_refcnt(mod))
		modEntry.Size = int(C.kmod_module_get_size(mod))

		holders := C.kmod_module_get_holders(mod)

		if holders != nil {
			var holdersEntry []string
			for hitr := holders; hitr != nil; hitr = C.kmod_list_next(holders, hitr) {
				hm := C.kmod_module_get_module(hitr)
				holdersEntry = append(holdersEntry, C.GoString(C.kmod_module_get_name(hm)))
				C.kmod_module_unref(hm)
			}

			modEntry.Holders = holdersEntry
		}

		if modinfo {
			kmi, err := getModInfo(ctx, modEntry.Name)
			modEntry.Info = kmi
			_ = err
		}
		ret = append(ret, modEntry)
		C.kmod_module_unref_list(holders)
		C.kmod_module_unref(mod)
	}

	C.kmod_module_unref_list(list)
	C.kmod_unref(ctx)

	return ret, err
}

func main() {
	ml, _ := GetKModList(true)
	mlj, _ := json.Marshal(ml)
	fmt.Println(string(mlj))
}
