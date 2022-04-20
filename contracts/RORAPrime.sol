// SPDX-License-Identifier: MIT

pragma solidity 0.8.11;

import '@openzeppelin/contracts/token/ERC20/ERC20.sol';
import '@openzeppelin/contracts/access/AccessControl.sol';
import '@openzeppelin/contracts/security/Pausable.sol';
import "./interfaces/ITransferRules.sol";

/// @title RoRa Prime (RORAP)
/// @author RoRa Group
/// @notice ERC-20 token with Access Control and ERC-1404 transfer restrictions.
/// Portions inspired by CoMakery Security Token

contract RORAPrime is ERC20, Pausable, AccessControl {

    ITransferRules public transferRules;

    bytes32 public constant CONTRACT_ADMIN_ROLE = keccak256("CONTRACT_ADMIN_ROLE");
    bytes32 public constant PERMISSIONS_ADMIN_ROLE = keccak256("PERMISSIONS_ADMIN_ROLE");
    bytes32 public constant MINT_ADMIN_ROLE = keccak256("MINT_ADMIN_ROLE");

    mapping(address => uint256) private _permissions;
    mapping(address => uint256) private _timeLock;

    event UpgradeRules(address indexed admin, address oldRules, address newRules);
    event PermissionChange(address indexed admin, address indexed account, uint256 permission);
    event AddressTimeLock(address indexed admin, address indexed account, uint256 value);

    constructor (string memory name_,
        string memory symbol_, 
        uint256 totalSupply_, 
        address mintAdmin_,
        address contractAdmin_, 
        address reserveAddress_,
        address transferRules_
        ) ERC20(name_, symbol_) {
        require(contractAdmin_ != address(0), "CONTRACT ADMIN ADDRESS CANNOT BE 0x0");
        require(mintAdmin_ != address(0), "MINT ADMIN ADDRESS CANNOT BE 0x0");
        require(reserveAddress_ != address(0), "RESERVE ADDRESS CANNOT BE 0x0");
        require(transferRules_ != address(0), "TRANSFER RULES ADDRESS CANNOT BE 0x0");
        require(mintAdmin_ != contractAdmin_, "CONTRACT AND MINT ADMINS MUST BE DIFFERENT");

        transferRules = ITransferRules(transferRules_);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINT_ADMIN_ROLE, mintAdmin_);
        _grantRole(CONTRACT_ADMIN_ROLE, contractAdmin_);
        _grantRole(PERMISSIONS_ADMIN_ROLE, contractAdmin_);
   
        _setRoleAdmin(PERMISSIONS_ADMIN_ROLE, CONTRACT_ADMIN_ROLE);

        _mint(reserveAddress_, totalSupply_ );
    }

    function pause() external onlyRole(CONTRACT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(CONTRACT_ADMIN_ROLE) {
        _unpause();
    }

    function mint(address to, uint256 amount) external whenNotPaused onlyRole(MINT_ADMIN_ROLE) {
        _mint(to, amount);
    }

    // Ability to burn address by board decision only for regulatory requirements
    // Can only be called by the Mint Admin role
    function burn(address from, uint256 amount) external whenNotPaused onlyRole(MINT_ADMIN_ROLE) {
        _burn(from, amount);
    }

    function transfer(address to, uint256 amount) public override whenNotPaused returns (bool) {
        enforceTransferRestrictions(msg.sender, to, amount);
        super.transfer(to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public override whenNotPaused returns (bool) {
        enforceTransferRestrictions(from, to, amount);
        super.transferFrom(from, to, amount);
        return true;
    }

    // Sets the transfer permission bits for a participant
    function setPermission(address account, uint256 permission) onlyRole(PERMISSIONS_ADMIN_ROLE)  external {
        require(account != address(0), "ADDRESS CAN NOT BE 0x0");
        _permissions[account] = permission;
        emit PermissionChange(msg.sender, account, permission);
    }

    function getPermission(address account) external view returns (uint256) {
        return _permissions[account];
    }

    // Unix timestamp is the number of seconds since the Unix epoch of 00:00:00 UTC on 1 January 1970.
    function setTimeLock(address account, uint256 timestamp) external onlyRole(PERMISSIONS_ADMIN_ROLE) {
        require(account != address(0), "ADDRESS CAN NOT BE 0x0");
        _timeLock[account] = timestamp;
        emit AddressTimeLock(msg.sender, account, timestamp);
    }

    function removeTimeLock(address account) external onlyRole(PERMISSIONS_ADMIN_ROLE) {
        require(account != address(0), "ADDRESS CAN NOT BE 0x0");
        _timeLock[account] = 0;
        emit AddressTimeLock(msg.sender, account, 0);
    }

    function getTimeLock(address account) external view returns(uint256 timestamp) {
        return _timeLock[account];
    }

    function enforceTransferRestrictions(address from, address to, uint256 value) private view {
        uint8 restrictionCode = detectTransferRestriction(from, to, value);
        require(transferRules.checkSuccess(restrictionCode), messageForTransferRestriction(restrictionCode));
    }

    function detectTransferRestriction(address from, address to, uint256 value) public view returns(uint8) {
        return transferRules.detectTransferRestriction(address(this), from, to, value);
    }

    function messageForTransferRestriction(uint8 restrictionCode) public view returns(string memory) {
        return transferRules.messageForTransferRestriction(restrictionCode);
    }

    function renounceRole(bytes32 role, address account) public override {
        require(role != DEFAULT_ADMIN_ROLE, "CANNOT RENOUNCE DEFAULT ADMIN ROLE");
        require(hasRole(role, account), "ADDRESS DOES NOT HAVE ROLE"); 
        super.renounceRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public override onlyRole(getRoleAdmin(role)) {
        require(role != DEFAULT_ADMIN_ROLE, "CANNOT REVOKE DEFAULT ADMIN ROLE");
        require(hasRole(role, account), "ADDRESS DOES NOT HAVE ROLE"); 
        super.revokeRole(role, account);
    }
    function grantRole(bytes32 role, address account) public override onlyRole(getRoleAdmin(role)) {
        require(!hasRole(role, account), "ADDRESS ALREADY HAS ROLE"); 
        super.grantRole(role, account);
    }

    function upgradeTransferRules(ITransferRules newTransferRules) external onlyRole(CONTRACT_ADMIN_ROLE) {
        require(address(newTransferRules) != address(0x0), "ADDRESS CAN NOT BE 0x0");
        address oldRules = address(transferRules);
        transferRules = newTransferRules;
        emit UpgradeRules(msg.sender, oldRules, address(newTransferRules));
    }
}
