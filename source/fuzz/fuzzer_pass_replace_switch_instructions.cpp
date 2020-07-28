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

#include "source/fuzz/fuzzer_pass_replace_switch_instructions.h"

#include "source/fuzz/fuzzer_util.h"
#include "source/fuzz/instruction_descriptor.h"
#include "source/fuzz/transformation_replace_switch_instruction.h"

namespace spvtools {
namespace fuzz {

FuzzerPassReplaceSwitchInstructions::FuzzerPassReplaceSwitchInstructions(opt::IRContext* ir_context, TransformationContext* transformation_context, FuzzerContext* fuzzer_context, protobufs::TransformationSequence* transformations) : FuzzerPass(ir_context, transformation_context, fuzzer_context, transformations) {}

FuzzerPassReplaceSwitchInstructions::~FuzzerPassReplaceSwitchInstructions() = default;

void FuzzerPassReplaceSwitchInstructions::Apply() {
  for (auto& function : *GetIRContext()->module()) {
    for (auto& block : function) {
      // |block| termination instruction.
      auto termination_instruction = &*block.tail();

      // |termination_instruction| must be an OpSwitch instruction to consider applying the transformation.
      if (termination_instruction->opcode() != SpvOpSwitch) {
        continue;
      }

      // |termination_instruction| must has at least 1 (literal, label) pair.
      uint32_t literal_label_pair_count = termination_instruction->NumOperands() / 2 - 1;
      if (literal_label_pair_count == 0) {
        continue;
      }

      // Decides, at random, whether the transformation should be applied.
      if (!GetFuzzerContext()->ChoosePercentage(GetFuzzerContext()->GetChanceOfReplacingSwitchInstruction())) {
        continue;
      }

      // Make sure all OpSwitch literal operands are defined as constants.
      // These constants will be used as operands of OpIEqual instructions.
      for (uint32_t i = 0; i < literal_label_pair_count; i++) {
        uint32_t literal = termination_instruction->GetSingleWordOperand(2 * (i + 1));
        auto selector_type = GetIRContext()->get_type_mgr()->GetType(GetIRContext()->get_def_use_mgr()->GetDef(termination_instruction->GetSingleWordOperand(0))->type_id())->AsInteger();
        FindOrCreateIntegerConstant({literal}, selector_type->width(), selector_type->IsSigned(), false);
      }

      // Make sure the boolean type is defined.
      // It will be used as the result type of the OpIEqual instruction.
      FindOrCreateBoolType();

      // Applies the replace switch instruction transformation.
      ApplyTransformation(TransformationReplaceSwitchInstruction(GetFuzzerContext()->GetFreshIds(TransformationReplaceSwitchInstruction::GetRequiredFreshIdCount(termination_instruction)), MakeInstructionDescriptor(GetIRContext(), termination_instruction)));
    }
  }
}

}  // namespace fuzz
}  // namespace spvtools
