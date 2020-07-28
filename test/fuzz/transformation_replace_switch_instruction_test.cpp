// Copyright (c) 2020 André Perez Maselco
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "source/fuzz/transformation_replace_switch_instruction.h"
#include "source/fuzz/instruction_descriptor.h"
#include "test/fuzz/fuzz_test_util.h"

namespace spvtools {
namespace fuzz {
namespace {

TEST(TransformationSwitchInstructionTest, IsApplicable) {
  std::string shader = R"(
               OpCapability Shader
          %1 = OpExtInstImport "GLSL.std.450"
               OpMemoryModel Logical GLSL450
               OpEntryPoint Vertex %39 "main"

; Types
          %2 = OpTypeFloat 32
          %3 = OpTypeVector %2 4
          %4 = OpTypePointer Function %3
          %5 = OpTypeVoid
          %6 = OpTypeFunction %5
          %7 = OpTypeFunction %2 %4 %4

; Constant scalars
          %8 = OpConstant %2 1
          %9 = OpConstant %2 2
         %10 = OpConstant %2 3
         %11 = OpConstant %2 4
         %12 = OpConstant %2 5
         %13 = OpConstant %2 6
         %14 = OpConstant %2 7
         %15 = OpConstant %2 8

; Constant vectors
         %16 = OpConstantComposite %3 %8 %9 %10 %11
         %17 = OpConstantComposite %3 %12 %13 %14 %15

; dot product function
         %18 = OpFunction %2 None %7
         %19 = OpFunctionParameter %4
         %20 = OpFunctionParameter %4
         %21 = OpLabel
         %22 = OpLoad %3 %19
         %23 = OpLoad %3 %20
         %24 = OpCompositeExtract %2 %22 0
         %25 = OpCompositeExtract %2 %23 0
         %26 = OpFMul %2 %24 %25
         %27 = OpCompositeExtract %2 %22 1
         %28 = OpCompositeExtract %2 %23 1
         %29 = OpFMul %2 %27 %28
         %30 = OpCompositeExtract %2 %22 2
         %31 = OpCompositeExtract %2 %23 2
         %32 = OpFMul %2 %30 %31
         %33 = OpCompositeExtract %2 %22 3
         %34 = OpCompositeExtract %2 %23 3
         %35 = OpFMul %2 %33 %34
         %36 = OpFAdd %2 %26 %29
         %37 = OpFAdd %2 %32 %36
         %38 = OpFAdd %2 %35 %37
               OpReturnValue %38
               OpFunctionEnd

; main function
         %39 = OpFunction %5 None %6
         %40 = OpLabel
         %41 = OpVariable %4 Function
         %42 = OpVariable %4 Function
               OpStore %41 %16
               OpStore %42 %17
         %43 = OpFunctionCall %2 %18 %41 %42 ; dot product function call
               OpReturn
               OpFunctionEnd
  )";

  const auto env = SPV_ENV_UNIVERSAL_1_5;
  const auto consumer = nullptr;
  const auto context = BuildModule(env, consumer, shader, kFuzzAssembleOption);
  ASSERT_TRUE(IsValid(env, context.get()));

  FactManager fact_manager;
  spvtools::ValidatorOptions validator_options;
  TransformationContext transformation_context(&fact_manager,
                                               validator_options);

  // Tests undefined function call instruction.
  // ASSERT_FALSE(transformation.IsApplicable(context.get(), transformation_context));

  // Tests false function call instruction.
  //ASSERT_FALSE(transformation.IsApplicable(context.get(), transformation_context));

  // Tests applicable transformation.
  // ASSERT_TRUE(transformation.IsApplicable(context.get(), transformation_context));
}

TEST(TransformationSwitchInstructionTest, Apply) {
  std::string reference_shader = R"(
               OpCapability Shader
          %1 = OpExtInstImport "GLSL.std.450"
               OpMemoryModel Logical GLSL450
               OpEntryPoint Vertex %11 "main"

; Types
          %2 = OpTypeInt 32 1
          %3 = OpTypeBool
          %4 = OpTypeVoid
          %5 = OpTypeFunction %4

; Constant scalars
          %6 = OpConstant %2 0
          %7 = OpConstant %2 1
          %8 = OpConstant %2 2
          %9 = OpConstant %2 3
         %10 = OpConstant %2 4

; main function
         %11 = OpFunction %4 None %5

         %12 = OpLabel
               OpSelectionMerge %18 None
               OpSwitch %6 %17 1 %13 2 %14 3 %15 4 %16
; switch (0) {
;   case 1:
         %13 = OpLabel
               OpBranch %18
;     break;
;   case 2:
         %14 = OpLabel
               OpBranch %18
;     break;
;   case 3:
         %15 = OpLabel
               OpBranch %18
;     break;
;   case 4:
         %16 = OpLabel
               OpBranch %18
;     break;
;   default:
         %17 = OpLabel
               OpBranch %18
;     break;
; }

         %18 = OpLabel
               OpSelectionMerge %24 None
               OpSwitch %6 %19 1 %20 2 %21 3 %22 4 %23
; switch (0) {
;   default:
         %19 = OpLabel
               OpBranch %20
;   case 1:
         %20 = OpLabel
               OpBranch %24
;     break;
;   case 2:
         %21 = OpLabel
               OpBranch %24
;     break;
;   case 3:
         %22 = OpLabel
               OpBranch %24
;     break;
;   case 4:
         %23 = OpLabel
               OpBranch %24
;     break;
; }

         %24 = OpLabel
               OpSelectionMerge %30 None
               OpSwitch %6 %27 1 %25 2 %26 3 %28 4 %29
; switch (0) {
;   case 1:
         %25 = OpLabel
               OpBranch %30
;     break;
;   case 2:
         %26 = OpLabel
               OpBranch %30
;     break;
;   default:
         %27 = OpLabel
               OpBranch %28
;   case 3:
         %28 = OpLabel
               OpBranch %30
;     break;
;   case 4:
         %29 = OpLabel
               OpBranch %30
;     break;
; }

         %30 = OpLabel
               OpSelectionMerge %36 None
               OpSwitch %6 %35 1 %31 2 %32 3 %33 4 %34
; switch (0) {
;   case 1:
         %31 = OpLabel
               OpBranch %32
;   case 2:
         %32 = OpLabel
               OpBranch %33
;   case 3:
         %33 = OpLabel
               OpBranch %34
;   case 4:
         %34 = OpLabel
               OpBranch %35
;   default:
         %35 = OpLabel
               OpBranch %36
;     break;
; }
         %36 = OpLabel
               OpReturn
               OpFunctionEnd
  )";

  const auto env = SPV_ENV_UNIVERSAL_1_5;
  const auto consumer = nullptr;
  const auto context =
      BuildModule(env, consumer, reference_shader, kFuzzAssembleOption);
  ASSERT_TRUE(IsValid(env, context.get()));

  FactManager fact_manager;
  spvtools::ValidatorOptions validator_options;
  TransformationContext transformation_context(&fact_manager,
                                               validator_options);

  auto instruction_descriptor = MakeInstructionDescriptor(12, SpvOpSwitch, 0);
  auto transformation = TransformationReplaceSwitchInstruction({37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48}, instruction_descriptor);
  transformation.Apply(context.get(), &transformation_context);

  instruction_descriptor = MakeInstructionDescriptor(18, SpvOpSwitch, 0);
  transformation = TransformationReplaceSwitchInstruction({49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61}, instruction_descriptor);
  transformation.Apply(context.get(), &transformation_context);

  instruction_descriptor = MakeInstructionDescriptor(24, SpvOpSwitch, 0);
  transformation = TransformationReplaceSwitchInstruction({62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74}, instruction_descriptor);
  // transformation.Apply(context.get(), &transformation_context);

  instruction_descriptor = MakeInstructionDescriptor(30, SpvOpSwitch, 0);
  transformation = TransformationReplaceSwitchInstruction({73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84}, instruction_descriptor);
  // transformation.Apply(context.get(), &transformation_context);

  std::string variant_shader = R"(
               OpCapability Shader
          %1 = OpExtInstImport "GLSL.std.450"
               OpMemoryModel Logical GLSL450
               OpEntryPoint Vertex %11 "main"

; Types
          %2 = OpTypeInt 32 1
          %3 = OpTypeBool
          %4 = OpTypeVoid
          %5 = OpTypeFunction %4

; Constant scalars
          %6 = OpConstant %2 0
          %7 = OpConstant %2 1
          %8 = OpConstant %2 2
          %9 = OpConstant %2 3
         %10 = OpConstant %2 4

; main function
         %11 = OpFunction %4 None %5
         %12 = OpLabel
         %37 = OpIEqual %3 %6 %7
         %38 = OpIEqual %3 %6 %8
         %39 = OpIEqual %3 %6 %9
         %40 = OpIEqual %3 %6 %10
         %41 = OpLogicalOr %3 %37 %38
         %42 = OpLogicalOr %3 %39 %41
         %43 = OpLogicalOr %3 %40 %42
         %44 = OpLogicalNot %3 %43
               OpSelectionMerge %45 None
               OpBranchConditional %37 %13 %45
; if (0 == 1) {
         %13 = OpLabel
               OpBranch %45
; }
         %45 = OpLabel
               OpSelectionMerge %46 None
               OpBranchConditional %38 %14 %46
; if (0 == 2) {
         %14 = OpLabel
               OpBranch %46
; }
         %46 = OpLabel
               OpSelectionMerge %47 None
               OpBranchConditional %39 %15 %47
; if (0 == 3) {
         %15 = OpLabel
               OpBranch %47
; }
         %47 = OpLabel
               OpSelectionMerge %48 None
               OpBranchConditional %40 %16 %48
; if (0 == 4) {
         %16 = OpLabel
               OpBranch %48
; }
         %48 = OpLabel
               OpSelectionMerge %18 None
               OpBranchConditional %44 %17 %18
; if (!(0 == 1 || 0 == 2 || 0 == 3 || 0 == 4)) {
         %17 = OpLabel
               OpBranch %18
; }

         %18 = OpLabel
         %49 = OpIEqual %3 %6 %7
         %50 = OpIEqual %3 %6 %8
         %51 = OpIEqual %3 %6 %9
         %52 = OpIEqual %3 %6 %10
         %53 = OpLogicalOr %3 %49 %50
         %54 = OpLogicalOr %3 %51 %53
         %55 = OpLogicalOr %3 %52 %54
         %56 = OpLogicalNot %3 %55
         %57 = OpLogicalOr %3 %49 %56
               OpSelectionMerge %58 None
               OpBranchConditional %57 %20 %58
; if (0 == 1 || !(0 == 1 || 0 == 2 || 0 == 3 || 0 == 4)) {
         %20 = OpLabel
               OpBranch %58
; }
         %58 = OpLabel
               OpSelectionMerge %59 None
               OpBranchConditional %50 %21 %59
; if (0 == 2) {
         %21 = OpLabel
               OpBranch %59
; }
         %59 = OpLabel
               OpSelectionMerge %60 None
               OpBranchConditional %51 %22 %60
; if (0 == 3) {
         %22 = OpLabel
               OpBranch %60
; }
         %60 = OpLabel
               OpSelectionMerge %61 None
               OpBranchConditional %52 %23 %61
; if (0 == 4) {
         %23 = OpLabel
               OpBranch %61
; }
         %61 = OpLabel
               OpSelectionMerge %24 None
               OpBranchConditional %56 %19 %24
; if (!(0 == 1 || 0 == 2 || 0 == 3 || 0 == 4)) {
         %19 = OpLabel
               OpBranch %24
; }

         %24 = OpLabel
         %62 = OpIEqual %3 %6 %7
         %63 = OpIEqual %3 %6 %8
         %64 = OpIEqual %3 %6 %9
         %65 = OpIEqual %3 %6 %10
         %66 = OpLogicalOr %3 %62 %63
         %67 = OpLogicalOr %3 %64 %66
         %68 = OpLogicalOr %3 %65 %67
         %69 = OpLogicalNot %3 %68
               OpSelectionMerge %70 None
               OpBranchConditional %62 %25 %70
; if (0 == 1) {
         %25 = OpLabel
               OpBranch %70
; }
         %70 = OpLabel
               OpSelectionMerge %71 None
               OpBranchConditional %63 %26 %71
; if (0 == 2) {
         %26 = OpLabel
               OpBranch %71
; }
         %71 = OpLabel
         %72 = OpLogicalOr %3 %64 %69
               OpSelectionMerge %73 None
               OpBranchConditional %72 %28 %73
; if (0 == 3 || !(0 == 1 || 0 == 2 || 0 == 3 || 0 == 4)) {
         %28 = OpLabel
               OpBranch %73
; }
         %73 = OpLabel
               OpSelectionMerge %74 None
               OpBranchConditional %65 %29 %74
; if (0 == 4) {
         %29 = OpLabel
               OpBranch %74
; }
         %74 = OpLabel
               OpSelectionMerge %30 None
               OpBranchConditional %69 %27 %30
; if (!(0 == 1 || 0 == 2 || 0 == 3 || 0 == 4)) {
         %27 = OpLabel
               OpBranch %24
; }

         %30 = OpLabel
         %75 = OpIEqual %3 %6 %7
         %76 = OpIEqual %3 %6 %8
         %77 = OpIEqual %3 %6 %9
         %78 = OpIEqual %3 %6 %10
         %79 = OpLogicalOr %3 %75 %76
         %80 = OpLogicalOr %3 %77 %79
         %81 = OpLogicalOr %3 %78 %80
         %82 = OpLogicalNot %3 %81
               OpSelectionMerge %58 None
               OpBranchConditional %57 %20 %58
; if (0 == 1 || !(0 == 1 || 0 == 2 || 0 == 3 || 0 == 4)) {
         %20 = OpLabel
               OpBranch %58
; }
         %58 = OpLabel
               OpSelectionMerge %59 None
               OpBranchConditional %50 %21 %59
; if (0 == 2) {
         %21 = OpLabel
               OpBranch %59
; }
         %59 = OpLabel
               OpSelectionMerge %60 None
               OpBranchConditional %51 %22 %60
; if (0 == 3) {
         %22 = OpLabel
               OpBranch %60
; }
         %60 = OpLabel
               OpSelectionMerge %61 None
               OpBranchConditional %52 %23 %61
; if (0 == 4) {
         %23 = OpLabel
               OpBranch %61
; }
         %61 = OpLabel
               OpSelectionMerge %24 None
               OpBranchConditional %56 %19 %24
; if (!(0 == 1 || 0 == 2 || 0 == 3 || 0 == 4)) {
         %19 = OpLabel
               OpBranch %24
; }
         %24 = OpLabel
               OpReturn
               OpFunctionEnd
  )";

  ASSERT_TRUE(IsValid(env, context.get()));
  ASSERT_TRUE(IsEqual(env, variant_shader, context.get()));
}

}  // namespace
}  // namespace fuzz
}  // namespace spvtools
