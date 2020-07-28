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

#include "source/fuzz/fuzzer_util.h"
#include "source/fuzz/instruction_descriptor.h"

namespace spvtools {
namespace fuzz {

TransformationReplaceSwitchInstruction::TransformationReplaceSwitchInstruction(const spvtools::fuzz::protobufs::TransformationReplaceSwitchInstruction& message) : message_(message) {}

TransformationReplaceSwitchInstruction::TransformationReplaceSwitchInstruction(const std::vector<uint32_t>& fresh_ids, const protobufs::InstructionDescriptor& instruction_descriptor) {
  *message_.mutable_fresh_ids() = google::protobuf::RepeatedField<google::protobuf::uint32>(fresh_ids.begin(), fresh_ids.end());
  *message_.mutable_instruction_descriptor() = instruction_descriptor;
}

bool TransformationReplaceSwitchInstruction::IsApplicable(opt::IRContext* ir_context, const TransformationContext& /*unused*/) const {
  auto instruction = FindInstruction(message_.instruction_descriptor(), ir_context);

  // |instruction| must be an OpSwitch instruction.
  if (instruction->opcode() != SpvOpSwitch) {
    return false;
  }

  // |instruction| must has at least 1 (literal, label) pair.
  if (instruction->NumOperands() / 2 - 1 == 0) {
    return false;
  }

  // |message_.fresh_ids.size| must be the exact number of fresh ids needed to
  // apply the transformation.
  if (static_cast<uint32_t>(message_.fresh_ids().size()) != GetRequiredFreshIdCount(instruction)) {
    return false;
  }

  // All ids in |message_.fresh_ids| must be fresh.
  for (uint32_t fresh_id : message_.fresh_ids()) {
    if (!fuzzerutil::IsFreshId(ir_context, fresh_id)) {
      return false;
    }
  }

  return true;
}

void TransformationReplaceSwitchInstruction::Apply(opt::IRContext* ir_context, TransformationContext* transformation_context) const {
  auto switch_instruction = FindInstruction(message_.instruction_descriptor(), ir_context);
  auto selector_instruction = ir_context->get_def_use_mgr()->GetDef(switch_instruction->GetSingleWordOperand(0));
  auto default_block = ir_context->cfg()->block(switch_instruction->GetSingleWordOperand(1));
  auto function = default_block->GetParent();
  auto selection_header = ir_context->get_instr_block(switch_instruction);
  auto merge_instruction = selection_header->GetMergeInst();

  // Gets the case constructs.
  uint32_t fresh_id_index = 0;
  std::map<uint32_t, uint32_t> case_to_condition;
  uint32_t num_operands = switch_instruction->NumOperands() / 2;
  for (uint32_t i = 0; i < num_operands - 1; i++) {
    uint32_t scalar_constant = fuzzerutil::MaybeGetScalarConstant(ir_context,
                                                          *transformation_context,
                                                          {switch_instruction->GetSingleWordOperand(2)},
                                                          selector_instruction->type_id(), false);

    // Inserts an OpIEqual instruction before the merge instruction.
    case_to_condition[switch_instruction->GetSingleWordOperand(3)] = message_.fresh_ids(fresh_id_index++);
    merge_instruction->InsertBefore(MakeUnique<opt::Instruction>(ir_context,
                                                                 SpvOpIEqual,
                                                                 fuzzerutil::MaybeGetBoolType(ir_context),
                                                                 case_to_condition[switch_instruction->GetSingleWordOperand(3)],
                                               opt::Instruction::OperandList({{SPV_OPERAND_TYPE_ID, {selector_instruction->result_id()}},
                                                                              {SPV_OPERAND_TYPE_ID, {scalar_constant}}})));

    // This iteration is also used to remove the (literal, label) operands because
    // the OpSwitch instruction will be changed to the first OpBranchConditional instruction.
    switch_instruction->RemoveOperand(2);
    switch_instruction->RemoveOperand(2);
  }

  auto map_iterator = case_to_condition.begin();
  // The default condition is an OpLogicalNot of OpLogicalOr instructions.
  std::vector<uint32_t> logical_or_ids;
  logical_or_ids.push_back(message_.fresh_ids(fresh_id_index++));
  merge_instruction->InsertBefore(MakeUnique<opt::Instruction>(ir_context,
                                                               SpvOpLogicalOr,
                                                               fuzzerutil::MaybeGetBoolType(ir_context),
                                                               logical_or_ids.back(),
                                                      opt::Instruction::OperandList({{SPV_OPERAND_TYPE_ID, {map_iterator->second}},
                                                                                   {SPV_OPERAND_TYPE_ID, {(++map_iterator)->second}}})));

  for (uint32_t i = 2; i < num_operands - 1; i++) {
    logical_or_ids.push_back(message_.fresh_ids(fresh_id_index++));
    merge_instruction->InsertBefore(MakeUnique<opt::Instruction>(ir_context,
                                                                 SpvOpLogicalOr,
                                                                 fuzzerutil::MaybeGetBoolType(ir_context),
                                                                 logical_or_ids.back(),
                                                   opt::Instruction::OperandList({{SPV_OPERAND_TYPE_ID, {(++map_iterator)->second}},
                                                                                      {SPV_OPERAND_TYPE_ID, {logical_or_ids[i - 2]}}})));
  }

  // The last |branch_condition_ids| element is the default condition.
  case_to_condition[default_block->id()] = message_.fresh_ids(fresh_id_index++);
  merge_instruction->InsertBefore(MakeUnique<opt::Instruction>(ir_context,
                                                               SpvOpLogicalNot,
                                                               fuzzerutil::MaybeGetBoolType(ir_context),
                                                               case_to_condition[default_block->id()],
                                                       opt::Instruction::OperandList({{SPV_OPERAND_TYPE_ID, {logical_or_ids.back()}}})));

  std::vector<opt::BasicBlock*> blocks;
  auto switch_block = function->FindBlock(selection_header->id());
  auto merge_block = function->FindBlock(merge_instruction->GetSingleWordOperand(0));
  for (auto case_block = ++switch_block; case_block != merge_block; ++case_block) {
    blocks.push_back(&*case_block);
  }

  // The OpSwitch instruction is changed to the first OpBranchConditional instruction.
  switch_instruction->SetOpcode(SpvOpBranchConditional);
  switch_instruction->SetOperand(0, {case_to_condition[blocks[0]->id()]});
  switch_instruction->SetOperand(1, {blocks[0]->id()});
  switch_instruction->AddOperand({SPV_OPERAND_TYPE_ID, {message_.fresh_ids(fresh_id_index)}});

  // Creates the selection headers.
  for (uint32_t i = 1; i < blocks.size(); i++) {
    auto selection_header1 = MakeUnique<opt::BasicBlock>(MakeUnique<opt::Instruction>(ir_context,
                                                                                SpvOpLabel, 0,
                                                                                message_.fresh_ids(fresh_id_index++),
                                                                                opt::Instruction::OperandList()));

    if (blocks[i - 1]->IsSuccessor(blocks[i])) {
      // If the current case construct is successor of the preceding case construct or
      // if the default case construct is successor of the preceding case construct and
      // and the current case construct is successor of the default case construct,
      // then the current case condition is changed to an OpLogicalOr including the preceding and
      // the current case conditions.
      selection_header1->AddInstruction(MakeUnique<opt::Instruction>(ir_context,
                                                                    SpvOpLogicalOr,
                                                                    fuzzerutil::MaybeGetBoolType(ir_context),
                                                                    message_.fresh_ids(fresh_id_index),
                                    opt::Instruction::OperandList({{SPV_OPERAND_TYPE_ID, {case_to_condition[blocks[i]->id()]}},
                                                                   {SPV_OPERAND_TYPE_ID, {case_to_condition[blocks[i - 1]->id()]}}})));
      case_to_condition[blocks[i]->id()] = message_.fresh_ids(fresh_id_index++);
    }

    // Inserts the OpSelectionMerge instruction into |selection_header|.
    selection_header1->AddInstruction(MakeUnique<opt::Instruction>(ir_context,
                                                                  SpvOpSelectionMerge, 0, 0,
                    opt::Instruction::OperandList({{SPV_OPERAND_TYPE_ID, {blocks[i] == blocks.back() ? merge_block->id() : message_.fresh_ids(fresh_id_index)}},
                                                                 {SPV_OPERAND_TYPE_SELECTION_CONTROL, {SpvSelectionControlMaskNone}}})));

    // Inserts the OpBranchConditional instruction into |selection_header|.
    selection_header1->AddInstruction(MakeUnique<opt::Instruction>(ir_context,
                                                                  SpvOpBranchConditional, 0, 0,
                                         opt::Instruction::OperandList({{SPV_OPERAND_TYPE_ID, {case_to_condition[blocks[i]->id()]}},
                                                                         {SPV_OPERAND_TYPE_ID, {blocks[i]->id()}},
                                                                         {SPV_OPERAND_TYPE_ID, {blocks[i] == blocks.back() ? merge_block->id() : message_.fresh_ids(fresh_id_index)}}})));

    // literal_label_pairs[i - 1].second->terminator()->SetOperand(0, {selection_header->id()});
    function->InsertBasicBlockBefore(std::move(selection_header1), blocks[i]);
  }

  //auto containing_function = case_constructs.back()->GetParent();
  //uint32_t default_block = case_constructs.back()->id();
  //containing_function->MoveBasicBlockToAfter(case_constructs.back()->id(), case_constructs[case_constructs.size() - 2]);
  //containing_function->InsertBasicBlockBefore(std::move(selection_header), ir_context->cfg()->block(default_block));

  //for (uint32_t i = 1; i < case_constructs.size(); i++) {
    //case_constructs[i - 1]->terminator()->SetOperand(0, {selection_header_ids[i]});
  //}

  fuzzerutil::UpdateModuleIdBound(ir_context, message_.fresh_ids(message_.fresh_ids().size() - 1));
  ir_context->InvalidateAnalysesExceptFor(opt::IRContext::kAnalysisNone);
}

protobufs::Transformation TransformationReplaceSwitchInstruction::ToMessage() const {
  protobufs::Transformation result;
  *result.mutable_replace_switch_instruction() = message_;
  return result;
}

uint32_t TransformationReplaceSwitchInstruction::GetRequiredFreshIdCount(opt::Instruction* switch_instruction) {
  // The number of fresh ids needed to apply the transformation depends on how many (literal, label) pairs the instruction has.
  // For each (literal, label) pair, 1 OpIEqual and 1 OpLabel instructions will be inserted.
  return switch_instruction->NumOperands() - 1;
}

}  // namespace fuzz
}  // namespace spvtools
