// Copyright (c) 2020 Google LLC
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

#ifndef SOURCE_FUZZ_TRANSFORMATION_SWAP_COMMUTABLE_OPERANDS_H_
#define SOURCE_FUZZ_TRANSFORMATION_SWAP_COMMUTABLE_OPERANDS_H_

#include "source/fuzz/fact_manager.h"
#include "source/fuzz/protobufs/spirvfuzz_protobufs.h"
#include "source/fuzz/transformation.h"
#include "source/opt/ir_context.h"

namespace spvtools {
namespace fuzz {

class TransformationSwapCommutableOperands : public Transformation {
 public:
  explicit TransformationSwapCommutableOperands(
    const protobufs::TransformationSwapCommutableOperands& message
  );

  TransformationSwapCommutableOperands(
    const protobufs::InstructionDescriptor& instruction_descriptor
  );

  // The transformation is applicable if the opcode represents
  // a commutative instruction.
  bool IsApplicable(opt::IRContext* context,
                    const FactManager& fact_manager) const override;

  // Swaps the commutable operands.
  void Apply(opt::IRContext* context, FactManager* fact_manager) const override;

  protobufs::Transformation ToMessage() const override;

 private:
  protobufs::TransformationSwapCommutableOperands message_;
};

}  // namespace fuzz
}  // namespace spvtools

#endif  // SOURCE_FUZZ_TRANSFORMATION_SWAP_COMMUTABLE_OPERANDS_H_
