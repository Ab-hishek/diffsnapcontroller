//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ChangedBlock) DeepCopyInto(out *ChangedBlock) {
	*out = *in
	if in.Context != nil {
		in, out := &in.Context, &out.Context
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ChangedBlock.
func (in *ChangedBlock) DeepCopy() *ChangedBlock {
	if in == nil {
		return nil
	}
	out := new(ChangedBlock)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GetChangedBlocks) DeepCopyInto(out *GetChangedBlocks) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GetChangedBlocks.
func (in *GetChangedBlocks) DeepCopy() *GetChangedBlocks {
	if in == nil {
		return nil
	}
	out := new(GetChangedBlocks)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GetChangedBlocks) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GetChangedBlocksList) DeepCopyInto(out *GetChangedBlocksList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]GetChangedBlocks, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GetChangedBlocksList.
func (in *GetChangedBlocksList) DeepCopy() *GetChangedBlocksList {
	if in == nil {
		return nil
	}
	out := new(GetChangedBlocksList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GetChangedBlocksList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GetChangedBlocksSpec) DeepCopyInto(out *GetChangedBlocksSpec) {
	*out = *in
	if in.Secrets != nil {
		in, out := &in.Secrets, &out.Secrets
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Parameters != nil {
		in, out := &in.Parameters, &out.Parameters
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GetChangedBlocksSpec.
func (in *GetChangedBlocksSpec) DeepCopy() *GetChangedBlocksSpec {
	if in == nil {
		return nil
	}
	out := new(GetChangedBlocksSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GetChangedBlocksStatus) DeepCopyInto(out *GetChangedBlocksStatus) {
	*out = *in
	if in.ChangeBlockList != nil {
		in, out := &in.ChangeBlockList, &out.ChangeBlockList
		*out = make([]ChangedBlock, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GetChangedBlocksStatus.
func (in *GetChangedBlocksStatus) DeepCopy() *GetChangedBlocksStatus {
	if in == nil {
		return nil
	}
	out := new(GetChangedBlocksStatus)
	in.DeepCopyInto(out)
	return out
}
