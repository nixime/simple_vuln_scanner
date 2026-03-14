Function GET_CVSS(AV_str As String, AC_str As String, PR_str As String, UI_str As String, S_str As String, C_str As String, I_str As String, A_str As String) As Double
    Dim AV, AC, PR, UI, C, I, A, ISS, Impact, Exploitability, Score As Double
    
    ' 1. Map String Values to Weights
    Select Case AV_str
        Case "Network": AV = 0.85 : Case "Adjacent": AV = 0.62 : Case "Local": AV = 0.55 : Case "Physical": AV = 0.2
    End Select
    
    Select Case AC_str
        Case "Low": AC = 0.77 : Case "High": AC = 0.44
    End Select
    
    ' PR depends on Scope
    If S_str = "Unchanged" Then
        Select Case PR_str
            Case "None": PR = 0.85 : Case "Low": PR = 0.62 : Case "High": PR = 0.27
        End Select
    Else
        Select Case PR_str
            Case "None": PR = 0.85 : Case "Low": PR = 0.68 : Case "High": PR = 0.5
        End Select
    End If
    
    Select Case UI_str
        Case "None": UI = 0.85 : Case "Required": UI = 0.62
    End Select
    
    ' CIA Weights
    Select Case C_str
        Case "None": C = 0 : Case "Low": C = 0.22 : Case "High": C = 0.56
    End Select
    Select Case I_str
        Case "None": I = 0 : Case "Low": I = 0.22 : Case "High": I = 0.56
    End Select
    Select Case A_str
        Case "None": A = 0 : Case "Low": A = 0.22 : Case "High": A = 0.56
    End Select

    ' 2. Calculate Impact Sub Score (ISS)
    ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
    
    ' 3. Calculate Impact
    If S_str = "Unchanged" Then
        Impact = 6.42 * ISS
    Else
        Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS * 0.9731 - 0.02) ^ 15
    End If
    
    ' 4. Calculate Exploitability
    Exploitability = 8.22 * AV * AC * PR * UI
    
    ' 5. Calculate Final Base Score
    If Impact <= 0 Then
        Score = 0
    Else
        If S_str = "Unchanged" Then
            Score = WorksheetFunction_RoundUp(Min(Impact + Exploitability, 10), 1)
        Else
            Score = WorksheetFunction_RoundUp(Min(1.08 * (Impact + Exploitability), 10), 1)
        End If
    End If
    
    GET_CVSS = Score
End Function

' Helper for Roundup (since Basic doesn't have it natively)
Function WorksheetFunction_RoundUp(val As Double, digits As Integer) As Double
    Dim factor As Double
    factor = 10 ^ digits
    WorksheetFunction_RoundUp = Int(val * factor + 0.9999999999) / factor
End Function

Function Min(a, b)
    If a < b Then Min = a Else Min = b
End Function
