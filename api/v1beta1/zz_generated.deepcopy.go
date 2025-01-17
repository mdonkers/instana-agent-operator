// +build !ignore_autogenerated

/*
(c) Copyright IBM Corp.
(c) Copyright Instana Inc.

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

// Code generated by controller-gen. DO NOT EDIT.

package v1beta1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InstanaAgent) DeepCopyInto(out *InstanaAgent) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InstanaAgent.
func (in *InstanaAgent) DeepCopy() *InstanaAgent {
	if in == nil {
		return nil
	}
	out := new(InstanaAgent)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *InstanaAgent) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InstanaAgentList) DeepCopyInto(out *InstanaAgentList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]InstanaAgent, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InstanaAgentList.
func (in *InstanaAgentList) DeepCopy() *InstanaAgentList {
	if in == nil {
		return nil
	}
	out := new(InstanaAgentList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *InstanaAgentList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InstanaAgentSpec) DeepCopyInto(out *InstanaAgentSpec) {
	*out = *in
	if in.ConfigurationFiles != nil {
		in, out := &in.ConfigurationFiles, &out.ConfigurationFiles
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	out.AgentCpuReq = in.AgentCpuReq.DeepCopy()
	out.AgentCpuLim = in.AgentCpuLim.DeepCopy()
	out.AgentMemReq = in.AgentMemReq.DeepCopy()
	out.AgentMemLim = in.AgentMemLim.DeepCopy()
	if in.AgentEnv != nil {
		in, out := &in.AgentEnv, &out.AgentEnv
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InstanaAgentSpec.
func (in *InstanaAgentSpec) DeepCopy() *InstanaAgentSpec {
	if in == nil {
		return nil
	}
	out := new(InstanaAgentSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InstanaAgentStatus) DeepCopyInto(out *InstanaAgentStatus) {
	*out = *in
	out.ServiceAccount = in.ServiceAccount
	out.ClusterRole = in.ClusterRole
	out.ClusterRoleBinding = in.ClusterRoleBinding
	out.Secret = in.Secret
	out.ConfigMap = in.ConfigMap
	out.DaemonSet = in.DaemonSet
	out.LeadingAgentPod = in.LeadingAgentPod
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InstanaAgentStatus.
func (in *InstanaAgentStatus) DeepCopy() *InstanaAgentStatus {
	if in == nil {
		return nil
	}
	out := new(InstanaAgentStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ResourceInfo) DeepCopyInto(out *ResourceInfo) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ResourceInfo.
func (in *ResourceInfo) DeepCopy() *ResourceInfo {
	if in == nil {
		return nil
	}
	out := new(ResourceInfo)
	in.DeepCopyInto(out)
	return out
}
