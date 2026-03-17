Option VBASupport 1
Option Explicit

' --- CVSS Weights: Metric Values ---
' Added N/A constant
Private Const VAL_NA As Double = 0

Private Const AV_NETWORK As Double = 0.85, AV_ADJACENT As Double = 0.62, AV_LOCAL As Double = 0.55, AV_PHYSICAL As Double = 0.2
Private Const AC_LOW As Double = 0.77, AC_HIGH As Double = 0.44
Private Const UI_NONE As Double = 0.85, UI_REQUIRED As Double = 0.62

' Privileges Required: Unchanged Scope
Private Const PR_U_NONE As Double = 0.85, PR_U_LOW As Double = 0.62, PR_U_HIGH As Double = 0.27
' Privileges Required: Changed Scope
Private Const PR_C_NONE As Double = 0.85, PR_C_LOW As Double = 0.68, PR_C_HIGH As Double = 0.5

' CIA Weights
Private Const CIA_NONE As Double = 0, CIA_LOW As Double = 0.22, CIA_HIGH As Double = 0.56

' --- CVSS Coefficients ---
Private Const COEFF_EXPLOIT As Double = 8.22
Private Const COEFF_IMPACT_U As Double = 6.42
Private Const COEFF_IMPACT_C As Double = 7.52
Private Const COEFF_ADJ As Double = 0.029
Private Const COEFF_SCOPE_FACTOR As Double = 1.08

' -------------------------------------------------------------------------
' MAIN FUNCTION
' -------------------------------------------------------------------------
Function GET_CVSS(AV_str As String, AC_str As String, PR_str As String, UI_str As String, S_str As String, C_str As String, I_str As String, A_str As String) As Variant
    Dim AV As Double, AC As Double, PR As Double, UI As Double
    Dim C As Double, I As Double, A As Double, ISS As Double
    Dim Impact As Double, Exploitability As Double, Score As Double
    
    On Error GoTo ErrHandler

    ' 1. Map Attack Vector
    Select Case Trim(AV_str)
        Case "Network": AV = AV_NETWORK: Case "Adjacent": AV = AV_ADJACENT: Case "Local": AV = AV_LOCAL: Case "Physical": AV = AV_PHYSICAL
        Case "N/A": AV = VAL_NA
        Case Else: GoTo ErrHandler
    End Select
    
    ' 2. Map Attack Complexity
    Select Case Trim(AC_str)
        Case "Low": AC = AC_LOW: Case "High": AC = AC_HIGH
        Case "N/A": AC = VAL_NA
        Case Else: GoTo ErrHandler
    End Select
    
    ' 3. Map Privileges Required
    If Trim(S_str) = "Unchanged" Then
        Select Case Trim(PR_str)
            Case "None": PR = PR_U_NONE: Case "Low": PR = PR_U_LOW: Case "High": PR = PR_U_HIGH
            Case "N/A": PR = VAL_NA
            Case Else: GoTo ErrHandler
        End Select
    Else
        Select Case Trim(PR_str)
            Case "None": PR = PR_C_NONE: Case "Low": PR = PR_C_LOW: Case "High": PR = PR_C_HIGH
            Case "N/A": PR = VAL_NA
            Case Else: GoTo ErrHandler
        End Select
    End If
    
    ' 4. Map User Interaction
    Select Case Trim(UI_str)
        Case "None": UI = UI_NONE: Case "Required": UI = UI_REQUIRED
        Case "N/A": UI = VAL_NA
        Case Else: GoTo ErrHandler
    End Select
    
    ' 5. Map CIA Metrics
    C = GetCIA(C_str): I = GetCIA(I_str): A = GetCIA(A_str)
    If C < 0 Or I < 0 Or A < 0 Then GoTo ErrHandler

    ' --- CALCULATION ---
    ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
    
    If Trim(S_str) = "Unchanged" Then
        Impact = COEFF_IMPACT_U * ISS
    Else
        Impact = COEFF_IMPACT_C * (ISS - COEFF_ADJ) - 3.25 * (ISS * 0.9731 - 0.02) ^ 13
    End If
    
    ' If any exploitability factor is N/A (0), Exploitability becomes 0
    Exploitability = COEFF_EXPLOIT * AV * AC * PR * UI
    
    If Impact <= 0 Then
        Score = 0
    Else
        If Trim(S_str) = "Unchanged" Then
            Score = Impact + Exploitability
        Else
            Score = COEFF_SCOPE_FACTOR * (Impact + Exploitability)
        End If
        If Score > 10 Then Score = 10
    End If
    
    ' Final Score Rounding
    GET_CVSS = Int(Score * 10 + 0.9999999) / 10
    Exit Function

ErrHandler:
    GET_CVSS = "Invalid Input"
End Function

Private Function GetCIA(val As String) As Double
    Select Case Trim(val)
        Case "None": GetCIA = CIA_NONE: Case "Low": GetCIA = CIA_LOW: Case "High": GetCIA = CIA_HIGH
        Case Else: GetCIA = -1
    End Select
End Function