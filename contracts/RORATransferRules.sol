// SPDX-License-Identifier: MIT

pragma solidity 0.8.11;
import './interfaces/ITransferRules.sol';

interface IRORA {
    function getTimeLock(address account) external view returns (uint256);
    function getPermission(address account) external view returns (uint256);
}

contract RORATransferRules is ITransferRules {
  
    mapping(uint8 => string) internal errorMessage;

    uint8 private constant SUCCESS = 0;
    uint8 private constant DO_NOT_SEND_TO_EMPTY_ADDRESS = 1;
    uint8 private constant DO_NOT_SEND_TO_TOKEN_CONTRACT = 2;
    uint8 private constant NO_ZERO_AMOUNT = 3;
    uint8 private constant SENDER_TOKENS_TIME_LOCKED = 4;
    uint8 private constant SENDER_ADDRESS_FROZEN = 5;
    uint8 private constant RECIPIENT_ADDRESS_FROZEN = 6;
    uint8 private constant FROZEN = 0x4;

constructor() {

    errorMessage[SUCCESS] = "SUCCESS";
    errorMessage[DO_NOT_SEND_TO_EMPTY_ADDRESS] = "DO NOT SEND TO EMPTY ADDRESS";
    errorMessage[DO_NOT_SEND_TO_TOKEN_CONTRACT] = "DO NOT SEND TO TOKEN CONTRACT";
    errorMessage[NO_ZERO_AMOUNT] = "AMOUNT CAN NOT BE 0";
    errorMessage[SENDER_TOKENS_TIME_LOCKED] = "SENDER TOKENS TIME LOCKED";
    errorMessage[SENDER_ADDRESS_FROZEN] = "SENDER ADDRESS FROZEN";
    errorMessage[RECIPIENT_ADDRESS_FROZEN] = "RECIPIENT ADDRESS FROZEN";
}

  function detectTransferRestriction(
    address _token,
    address from,
    address to,
    uint256 value
  )
    external
    override
    view
    returns(uint8)
  {
    IRORA token = IRORA(_token);

    if (to == address(0)) return DO_NOT_SEND_TO_EMPTY_ADDRESS;
    if (to == address(token)) return DO_NOT_SEND_TO_TOKEN_CONTRACT;
    if (value == 0) return NO_ZERO_AMOUNT;
    if (block.timestamp < token.getTimeLock(from)) return SENDER_TOKENS_TIME_LOCKED;
    if (token.getPermission(from) & FROZEN == FROZEN) return SENDER_ADDRESS_FROZEN;
    if (token.getPermission(to) & FROZEN == FROZEN) return RECIPIENT_ADDRESS_FROZEN;

    return SUCCESS;
  }

  function messageForTransferRestriction(uint8 restrictionCode)
    external
    override
    view
    returns(string memory)
  {
    require(restrictionCode <= 6, "BAD RESTRICTION CODE");
    return errorMessage[restrictionCode];
  }

  function checkSuccess(uint8 restrictionCode) external override pure returns (bool isSuccess) {
    return restrictionCode == SUCCESS;
  }
}